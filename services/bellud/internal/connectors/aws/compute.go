package aws

import (
	"context"
	"strings"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/aws/awsschema"
)

// This file holds the steps for the types the collector emitted before the
// network registry: instances, buckets, roles, functions, and databases.

func (r *run) ec2(ctx context.Context, rg string) error {
	l, err := r.c.client.Instances(ctx, rg)
	r.truncate("ec2", rg, l.Truncated)
	r.instances[rg] = l.Items
	for _, i := range l.Items {
		arn := r.instARN(rg, i.ID)
		if !r.add(arn, "ec2", awsschema.TypeInstance, rg, map[string]any{
			"name": i.Name, "state": i.State, "instance_type": i.Type,
			"created_at": ts(i.LaunchTime), "tag_count": i.TagCount}) {
			continue
		}
		r.b.rel("runs_on", arn, r.vpcARN(rg, i.VPCID), nil)
		for _, e := range i.ENIIDs {
			r.b.rel("aws_has_eni", arn, r.eniARN(rg, e), nil)
		}
	}
	return err
}

func (r *run) s3(ctx context.Context, _ string) error {
	bs, err := r.c.client.Buckets(ctx)
	for _, k := range bs {
		if !r.selected[k.Region] {
			continue
		}
		arn := "arn:" + partition(k.Region) + ":s3:::" + k.Name
		attrs := map[string]any{"name": k.Name, "created_at": ts(k.CreatedAt)}
		sec, serr := r.c.client.BucketSecurity(ctx, k.Name, k.Region)
		if isRejected(serr) {
			return serr
		}
		r.dataAttrs(attrs, arn, sec)
		r.add(arn, "s3", awsschema.TypeBucket, k.Region, attrs)
	}
	return err
}

// dataAttrs sets the five data store attributes. Each failed call is a
// missing_data gap on the run status; the attributes it feeds stay unknown.
func (r *run) dataAttrs(attrs map[string]any, arn string, sec DataSecurity) {
	attrs["encryption_at_rest"] = sec.EncryptionAtRest
	attrs["encryption_in_transit"] = sec.EncryptionInTransit
	attrs["public_access"] = sec.PublicAccess
	attrs["backup"] = sec.Backup
	attrs["logging"] = sec.Logging
	if len(sec.Gaps) > 0 {
		attrs["missing_data"] = strings.Join(sec.Gaps, ",")
	}
	for _, g := range sec.Gaps {
		r.c.status.Deny("missing_data:" + g + "@" + arn)
	}
}

func (r *run) iam(ctx context.Context, _ string) error {
	rs, err := r.c.client.Roles(ctx)
	for _, x := range rs {
		r.add(x.ARN, "iam", awsschema.TypeRole, "", map[string]any{"name": x.Name, "created_at": ts(x.CreatedAt)})
	}
	return err
}

func (r *run) lambda(ctx context.Context, rg string) error {
	fs, err := r.c.client.Functions(ctx, rg)
	for _, f := range fs {
		r.add(f.ARN, "lambda", awsschema.TypeLambda, rg, map[string]any{"name": f.Name, "runtime": f.Runtime})
	}
	return err
}

func (r *run) rds(ctx context.Context, rg string) error {
	ds, err := r.c.client.DBInstances(ctx, rg)
	for _, d := range ds {
		attrs := map[string]any{
			"name": d.ID, "engine": d.Engine, "state": d.Status, "created_at": ts(d.CreatedAt)}
		// In-transit encryption needs the parameter group (rds.force_ssl); not read.
		r.dataAttrs(attrs, d.ARN, DataSecurity{
			EncryptionAtRest: state(d.StorageEncrypted), EncryptionInTransit: StateUnknown,
			PublicAccess: state(d.PubliclyAccessible), Backup: state(d.BackupRetention > 0),
			Logging: state(len(d.LogExports) > 0)})
		r.add(d.ARN, "rds", awsschema.TypeRDSInstance, rg, attrs)
	}
	return err
}
