package cveupdate

import (
	"context"
	"errors"
	"fmt"
	"io"
)

const (
	maxIndexBytes = 16 << 20
	indexSigRef   = "index.json.sig"
)

// Update runs `bellu cve update`: it requests the index with the stored ETag,
// stops on 304, verifies the index signature, and installs the planned packs.
// The last check time is recorded after a 304 and after a successful check;
// the stored ETag changes only when the installed snapshot is the one the
// index names, so a failed install is retried in full. A failure before the
// install appends one audit row, as the install does for its own failures.
func (u *Updater) Update(ctx context.Context) (Result, error) {
	if u.Client == nil || u.Verifier == nil || u.State == nil {
		return Result{}, errors.New("cveupdate: Client, Verifier and State are required")
	}
	etag, err := u.storedETag(ctx)
	if err != nil {
		return Result{}, u.auditPreInstall(ctx, StepPlan, err)
	}
	raw, newETag, err := u.fetchIndex(ctx, etag)
	if errors.Is(err, ErrNotModified) {
		return Result{Unchanged: true}, u.State.RecordCVECheck(ctx, u.now(), "")
	}
	if err != nil {
		return Result{}, u.auditPreInstall(ctx, StepDownload, err)
	}
	sig, err := readAll(ctx, u.Client, indexSigRef, maxSigBytes)
	if err != nil {
		return Result{}, u.auditPreInstall(ctx, StepDownload, fmt.Errorf("index signature: %w", err))
	}
	idx, err := u.Verifier.VerifyIndex(raw, sig)
	if err != nil {
		return Result{}, u.auditPreInstall(ctx, StepVerify, err)
	}
	res, err := u.InstallIndex(ctx, idx)
	if err != nil {
		return res, err
	}
	if cerr := u.State.RecordCVECheck(ctx, u.now(), newETag); cerr != nil && res.StateErr == nil {
		res.StateErr = cerr
	}
	return res, nil
}

func (u *Updater) storedETag(ctx context.Context) (string, error) {
	row, ok, err := u.State.GetCVEUpdateState(ctx)
	if err != nil || !ok || row.SnapshotID == "" {
		return "", err // a 304 with nothing installed would install nothing
	}
	return row.ETag, nil
}

func (u *Updater) fetchIndex(ctx context.Context, etag string) (raw []byte, newETag string, err error) {
	resp, err := u.Client.FetchIndex(ctx, etag)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, maxIndexBytes+1))
	if err == nil && len(raw) > maxIndexBytes {
		err = errors.New("index.json too large")
	}
	return raw, resp.ETag, err
}

func readAll(ctx context.Context, c *Client, ref string, limit int) ([]byte, error) {
	resp, err := c.FetchPack(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err == nil && len(b) > limit {
		err = errors.New("response too large")
	}
	return b, err
}

// auditPreInstall appends the failure row for an update that failed before the
// shared install ran, and returns err joined with any audit failure.
func (u *Updater) auditPreInstall(ctx context.Context, step string, err error) error {
	err = stepErr(step, err)
	if u.Audit == nil {
		return err
	}
	e := AuditEntry{At: u.now(), Action: "cve-update", Outcome: "failure", Step: step, Cause: err.Error()}
	if aerr := u.Audit.AppendCVEUpdate(context.WithoutCancel(ctx), e); aerr != nil {
		return errors.Join(err, fmt.Errorf("audit row not written: %w", aerr))
	}
	return err
}
