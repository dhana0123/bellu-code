package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
)

const (
	imdsBase    = "http://169.254.169.254"
	imdsMaxBody = 64 << 10
)

// ErrNoAmbientCredentials means neither the environment nor the instance
// metadata service supplied credentials.
var ErrNoAmbientCredentials = errors.New("aws: no ambient credentials")

// AmbientCredentials returns the credentials of the "ambient" source: the
// AWS_* environment variables first, then the EC2 instance role through imds
// (broker.IMDSClient, which can reach only the metadata service). The result
// is meant only as the base of sts:AssumeRole.
func AmbientCredentials(imds *http.Client, getenv func(string) string) awssdk.CredentialsProvider {
	return awssdk.CredentialsProviderFunc(func(ctx context.Context) (awssdk.Credentials, error) {
		if getenv != nil {
			id, secret := getenv("AWS_ACCESS_KEY_ID"), getenv("AWS_SECRET_ACCESS_KEY")
			if id != "" && secret != "" {
				return awssdk.Credentials{
					AccessKeyID: id, SecretAccessKey: secret,
					SessionToken: getenv("AWS_SESSION_TOKEN"), Source: "bellud-ambient-env",
				}, nil
			}
		}
		if imds == nil {
			return awssdk.Credentials{}, ErrNoAmbientCredentials
		}
		return imdsRoleCredentials(ctx, imds)
	})
}

func imdsRoleCredentials(ctx context.Context, c *http.Client) (awssdk.Credentials, error) {
	fail := func(err error) (awssdk.Credentials, error) {
		return awssdk.Credentials{}, fmt.Errorf("%w: %v", ErrNoAmbientCredentials, err)
	}
	token, err := imdsDo(ctx, c, http.MethodPut, "/latest/api/token", "")
	if err != nil {
		return fail(err)
	}
	roles, err := imdsDo(ctx, c, http.MethodGet, "/latest/meta-data/iam/security-credentials/", strings.TrimSpace(token))
	if err != nil {
		return fail(err)
	}
	role, _, _ := strings.Cut(strings.TrimSpace(roles), "\n")
	if role == "" || strings.ContainsAny(role, "/ ") {
		return fail(errors.New("no instance role"))
	}
	doc, err := imdsDo(ctx, c, http.MethodGet, "/latest/meta-data/iam/security-credentials/"+role, strings.TrimSpace(token))
	if err != nil {
		return fail(err)
	}
	var v struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string
		Token           string
		Expiration      time.Time
	}
	if err := json.Unmarshal([]byte(doc), &v); err != nil || v.AccessKeyID == "" || v.SecretAccessKey == "" {
		return fail(errors.New("malformed credential document"))
	}
	return awssdk.Credentials{
		AccessKeyID: v.AccessKeyID, SecretAccessKey: v.SecretAccessKey, SessionToken: v.Token,
		Source: "bellud-ambient-imds", CanExpire: !v.Expiration.IsZero(), Expires: v.Expiration,
	}, nil
}

func imdsDo(ctx context.Context, c *http.Client, method, path, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, method, imdsBase+path, nil)
	if err != nil {
		return "", err
	}
	if method == http.MethodPut {
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	} else {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, imdsMaxBody))
	return string(b), err
}
