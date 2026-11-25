package opname_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker/opname"
)

// recorder is a counting RoundTripper that resolves the operation name and
// replies with an empty 200 (the SDK deserialisation error is irrelevant).
type recorder struct {
	mu    sync.Mutex
	calls int
	name  string
	ok    bool
	body  string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	name, ok := opname.Resolve(req)
	var body string
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		body = string(raw)
	}
	r.mu.Lock()
	r.calls++
	r.name, r.ok, r.body = name, ok, body
	r.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func config(rt http.RoundTripper) aws.Config {
	return aws.Config{
		Region:           "us-east-1",
		Credentials:      credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "secret", ""),
		HTTPClient:       &http.Client{Transport: rt},
		RetryMaxAttempts: 1,
	}
}

func TestResolveSDKOperations(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		want string
		call func(cfg aws.Config)
	}{
		{"GetCallerIdentity", func(c aws.Config) { _, _ = sts.NewFromConfig(c).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}) }},
		{"AssumeRole", func(c aws.Config) {
			_, _ = sts.NewFromConfig(c).AssumeRole(ctx, &sts.AssumeRoleInput{
				RoleArn:         aws.String("arn:aws:iam::123456789012:role/r"),
				RoleSessionName: aws.String("s"),
			})
		}},
		{"DescribeInstances", func(c aws.Config) { _, _ = ec2.NewFromConfig(c).DescribeInstances(ctx, &ec2.DescribeInstancesInput{}) }},
		{"ListObjectsV2", func(c aws.Config) {
			_, _ = s3.NewFromConfig(c).ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String("sample-bucket"), MaxKeys: aws.Int32(5)})
		}},
		{"GetObject", func(c aws.Config) {
			_, _ = s3.NewFromConfig(c).GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String("sample-bucket"), Key: aws.String("d/k.txt"), Range: aws.String("bytes=0-9")})
		}},
		{"ListBuckets", func(c aws.Config) { _, _ = s3.NewFromConfig(c).ListBuckets(ctx, &s3.ListBucketsInput{}) }},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			rec := &recorder{}
			tc.call(config(rec))
			if rec.calls != 1 {
				t.Fatalf("calls = %d, want 1", rec.calls)
			}
			if !rec.ok || rec.name != tc.want {
				t.Fatalf("Resolve = (%q, %v), want (%q, true)", rec.name, rec.ok, tc.want)
			}
		})
	}
}

func TestResolveLeavesBodyReadable(t *testing.T) {
	rec := &recorder{}
	_, _ = sts.NewFromConfig(config(rec)).GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if !strings.Contains(rec.body, "Action=GetCallerIdentity") {
		t.Fatalf("body = %q, want Action=GetCallerIdentity", rec.body)
	}
}

func TestResolveDeniesMissingName(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://sts.us-east-1.amazonaws.com/",
		strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if name, ok := opname.Resolve(req); ok {
		t.Fatalf("Resolve = (%q, true), want denied", name)
	}
}

func TestResolveDeniesMismatch(t *testing.T) {
	// Real SDK name (DescribeInstances) but the wire says a different action.
	rt := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req.Body = io.NopCloser(strings.NewReader("Action=TerminateInstances&Version=2016-11-15"))
		if name, ok := opname.Resolve(req); ok {
			t.Errorf("Resolve = (%q, true), want denied on mismatch", name)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
	})
	_, _ = ec2.NewFromConfig(config(rt)).DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
