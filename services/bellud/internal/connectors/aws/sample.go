package aws

import (
	"context"
	"fmt"
	"io"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// SampleObjectBytes is the most bytes read from one sampled object (13.4).
const SampleObjectBytes = 64 * 1024

// ObjectSampler reads object content for data classification. Only the
// classifier uses it, and only for stores that opted in to sampling.
type ObjectSampler interface {
	// SampleObjects reads at most limit objects of the bucket with read-only
	// ListObjectsV2 and GetObject, at most maxBytes of each, and passes each
	// body to fn. fn must not retain or persist the slice.
	SampleObjects(ctx context.Context, bucket, region string, limit, maxBytes int, fn func(content []byte)) error
}

var _ ObjectSampler = (*client)(nil)

func (c *client) SampleObjects(ctx context.Context, bucket, region string, limit, maxBytes int, fn func([]byte)) error {
	cl, name := c.s3At(region), awssdk.String(bucket)
	read := 0
	var token *string
	for read < limit {
		page, err := cl.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: name, ContinuationToken: token, MaxKeys: awssdk.Int32(int32(min(limit-read, 1000))),
		})
		if err != nil {
			return fmt.Errorf("s3:ListObjectsV2: %w", mapErr(err))
		}
		for _, o := range page.Contents {
			if read >= limit {
				break
			}
			if awssdk.ToInt64(o.Size) == 0 {
				continue
			}
			read++
			out, err := cl.GetObject(ctx, &s3.GetObjectInput{
				Bucket: name, Key: o.Key, Range: awssdk.String(fmt.Sprintf("bytes=0-%d", maxBytes-1)),
			})
			if err != nil {
				return fmt.Errorf("s3:GetObject: %w", mapErr(err))
			}
			body, err := io.ReadAll(io.LimitReader(out.Body, int64(maxBytes)))
			_ = out.Body.Close()
			if err != nil {
				return fmt.Errorf("s3:GetObject: read body: %w", mapErr(err))
			}
			fn(body)
		}
		if !awssdk.ToBool(page.IsTruncated) || page.NextContinuationToken == nil {
			break
		}
		token = page.NextContinuationToken
	}
	return nil
}
