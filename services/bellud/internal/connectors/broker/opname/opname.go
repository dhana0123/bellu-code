// Package opname resolves the AWS operation name of an outgoing request inside
// an http.RoundTripper and fails closed.
//
// Mechanism (proven by opname_test.go): no fallback is needed. The SDK's
// RegisterServiceMetadata Initialize middleware stores the operation name in
// the middleware context, and the Smithy HTTP client builds the outgoing
// *http.Request with that context. awsmiddleware.GetOperationName(req.Context())
// therefore returns it inside the RoundTripper (verified for STS, EC2 and S3).
//
// The name is never trusted alone. It is cross-checked against the wire:
// the form body "Action=" (query protocol: STS, EC2), the X-Amz-Target header
// (JSON protocols), or, for REST protocols, a small method/path table
// (S3 ListBuckets). A missing name, a mismatch or an unrecognised wire shape
// returns ("", false).
package opname

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"

	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
)

// maxBody bounds how much of a request body is inspected for Action=.
const maxBody = 1 << 20

// Resolve returns the SDK operation name of req when it agrees with the wire
// action. It returns false when the name is missing or does not match. The
// request body is left readable.
func Resolve(req *http.Request) (string, bool) {
	if req == nil {
		return "", false
	}
	name := awsmiddleware.GetOperationName(req.Context())
	if name == "" {
		return "", false
	}
	wire, ok := wireAction(req)
	if !ok || wire != name {
		return "", false
	}
	return name, true
}

func wireAction(req *http.Request) (string, bool) {
	if target := req.Header.Get("X-Amz-Target"); target != "" {
		i := strings.LastIndexByte(target, '.')
		return target[i+1:], target[i+1:] != ""
	}
	if req.Method == http.MethodPost && isForm(req) {
		return formAction(req)
	}
	return restAction(req)
}

func isForm(req *http.Request) bool {
	return strings.HasPrefix(req.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
}

func formAction(req *http.Request) (string, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return "", false
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
	_ = req.Body.Close()
	// Restore the body so the transport can still send it.
	req.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil || len(raw) > maxBody {
		return "", false
	}
	vals, err := url.ParseQuery(string(raw))
	if err != nil {
		return "", false
	}
	actions := vals["Action"]
	if len(actions) != 1 || actions[0] == "" {
		return "", false
	}
	return actions[0], true
}

// restAction maps the few REST operations we allow by method and path.
func restAction(req *http.Request) (string, bool) {
	host := req.URL.Hostname()
	if req.Method == http.MethodGet && req.URL.Path == "/" && (req.URL.RawQuery == "" || req.URL.RawQuery == "x-id=ListBuckets") && isS3Service(host) {
		return "ListBuckets", true
	}
	if req.Method == http.MethodGet && req.URL.Path == "/" && strings.Contains(host, ".s3.") {
		return bucketAction(req.URL.Query())
	}
	// Content sampling (13.4): GET https://bucket.s3.../key?x-id=GetObject. Any
	// other query key (versionId, uploadId, acl, ...) is not recognised.
	if req.Method == http.MethodGet && len(req.URL.Path) > 1 && strings.Contains(host, ".s3.") {
		q := req.URL.Query()
		if len(q) == 1 && q.Get("x-id") == "GetObject" {
			return "GetObject", true
		}
	}
	return "", false
}

// bucketSubresources maps the read-only S3 bucket subresource query keys to
// their operation names (virtual-host style: GET https://bucket.s3.../?key).
var bucketSubresources = map[string]string{
	"encryption": "GetBucketEncryption", "publicAccessBlock": "GetPublicAccessBlock",
	"policyStatus": "GetBucketPolicyStatus", "logging": "GetBucketLogging", "versioning": "GetBucketVersioning",
}

// listObjectsKeys are the query keys ListObjectsV2 may carry besides list-type.
var listObjectsKeys = map[string]bool{
	"list-type": true, "max-keys": true, "prefix": true, "continuation-token": true,
	"start-after": true, "encoding-type": true, "delimiter": true, "fetch-owner": true, "x-id": true,
}

func bucketAction(q url.Values) (string, bool) {
	if q.Get("list-type") == "2" {
		for k := range q {
			if !listObjectsKeys[k] {
				return "", false
			}
		}
		if q.Has("x-id") && q.Get("x-id") != "ListObjectsV2" {
			return "", false
		}
		return "ListObjectsV2", true
	}
	op := ""
	for k := range q {
		if k == "x-id" {
			continue
		}
		name, ok := bucketSubresources[k]
		if !ok || op != "" {
			return "", false
		}
		op = name
	}
	if op == "" || (q.Has("x-id") && q.Get("x-id") != op) {
		return "", false
	}
	return op, true
}

// isS3Service matches the regional/global S3 service endpoints and rejects
// bucket virtual-host names such as "bucket.s3.us-east-1.amazonaws.com".
func isS3Service(host string) bool {
	return strings.HasPrefix(host, "s3.") || strings.HasPrefix(host, "s3-")
}
