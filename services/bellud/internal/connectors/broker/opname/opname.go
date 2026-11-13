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
	return "", false
}

// isS3Service matches the regional/global S3 service endpoints and rejects
// bucket virtual-host names such as "bucket.s3.us-east-1.amazonaws.com".
func isS3Service(host string) bool {
	return strings.HasPrefix(host, "s3.") || strings.HasPrefix(host, "s3-")
}
