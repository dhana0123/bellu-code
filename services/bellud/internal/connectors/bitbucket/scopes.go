package bitbucket

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
)

// Workspace is one selectable workspace.
type Workspace struct{ Slug, Name string }

// Workspaces lists the workspaces the token can read, for the scope step.
func (p *Provider) Workspaces(ctx context.Context, c lifecycle.Call) ([]Workspace, error) {
	if c.Client == nil {
		return nil, errors.New("bitbucket: no http client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+APIHost+"/2.0/workspaces?pagelen=100", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		return nil, mapError(&statusError{status: resp.StatusCode})
	}
	var out struct {
		Values []struct {
			Slug string `json:"slug"`
			Name string `json:"name"`
		} `json:"values"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out); err != nil {
		return nil, lifecycle.NewError(lifecycle.CodeValidationFailed, "unreadable response from Bitbucket", nil)
	}
	ws := make([]Workspace, 0, len(out.Values))
	for _, v := range out.Values {
		if v.Slug != "" {
			ws = append(ws, Workspace{Slug: clip(v.Slug), Name: clip(v.Name)})
		}
	}
	return ws, nil
}
