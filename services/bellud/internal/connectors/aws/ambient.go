package aws

import (
	"context"
	"net/http"
)

// AmbientIdentity runs "Detect principal" with the ambient credentials (AWS_*
// variables, then the instance role). imds reaches only the metadata service
// and sts only STS; both come from the broker with an ambient reference.
func (p *Provider) AmbientIdentity(ctx context.Context, imds, sts *http.Client, region string) (Identity, error) {
	creds := AmbientCredentials(imds, p.cfg.Getenv)
	cl, err := p.cfg.NewClient(Config{HTTPClient: sts, Credentials: creds, HomeRegion: region})
	if err != nil {
		return Identity{}, err
	}
	return DetectPrincipal(ctx, cl)
}
