package connectors

import (
	"context"

	"github.com/bellu/bellucode/services/bellud/internal/connectors/azure"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/broker"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/deviceflow"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/github"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/gitlab"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/lifecycle"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/policy"
	"github.com/bellu/bellucode/services/bellud/internal/connectors/store"
)

// newDeviceFlow builds the device authorization service on top of the broker
// and the lifecycle manager.
func (s *Service) newDeviceFlow() *deviceflow.Service {
	return deviceflow.New(deviceflow.Config{
		Clients:  s.broker,
		Registry: s.registry,
		Audit:    s.auditLog,
		Redactor: s.red,
		Store:    s.store,
		PreRef:   s.devicePreRef,
		Connect:  s.deviceConnect,
		Abandon:  s.mgr.Disconnect,
		Now:      s.now,
	})
}

func (s *Service) devicePreRef(connectorID, authID string) (broker.ConnectionRef, error) {
	e, ok := s.registry.Get(connectorID)
	if !ok {
		return broker.ConnectionRef{}, s.invalid("unknown connector", "connectorId")
	}
	// The connector's own sign-in host fills the manifest's host placeholder,
	// which Compile requires.
	pol, err := policy.Compile(e.Manifest, policy.Selection{Host: deviceHost(connectorID)})
	if err != nil {
		return broker.ConnectionRef{}, s.invalid("connection policy is invalid", "connectorId")
	}
	return broker.PreConnectionRef(connectorID, e.Manifest, pol, authID), nil
}

// deviceHost is the host used by a connector's pre-connection policy.
func deviceHost(connectorID string) string {
	switch connectorID {
	case gitlab.ConnectorID:
		return gitlab.GitLabHost
	case azure.ConnectorID:
		return azure.LoginHost
	}
	return github.DefaultAPIHost
}

// deviceConnect turns a device-flow token into a new Connection (method
// device) or replaces the credential of an EXPIRED or ERROR one.
func (s *Service) deviceConnect(ctx context.Context, req deviceflow.ConnectRequest) (store.Connection, error) {
	cred := lifecycle.CredentialInput{Secret: req.Token, ExpiresAt: req.ExpiresAt, RefreshToken: req.RefreshToken}
	if req.ReconnectID != "" {
		if err := s.mgr.ReconnectVerified(ctx, req.ReconnectID, cred); err != nil {
			return store.Connection{}, err
		}
		c, _ := s.store.Connection(req.ReconnectID)
		return c, nil
	}
	s.createMu.Lock()
	defer s.createMu.Unlock()
	s.nextID = randomID()
	defer func() { s.nextID = "" }()
	return s.mgr.Create(ctx, lifecycle.CreateInput{
		ConnectorID: req.ConnectorID, Alias: req.Alias, AuthConfigID: lifecycle.DefaultAuthConfigID(req.ConnectorID),
		Method: lifecycle.MethodDevice, Selection: store.Selection{Regions: []string{}, Repos: []string{}},
		Credential: cred,
	})
}

// StartDeviceAuthorization begins a device authorization.
func (s *Service) StartDeviceAuthorization(ctx context.Context, in deviceflow.StartInput) (deviceflow.Authorization, error) {
	if !s.Enabled() {
		return deviceflow.Authorization{}, ErrDisabled
	}
	return s.device.Start(ctx, in)
}

// DeviceAuthorizationStatus reports the state of an authorization
// (deviceflow.ErrNotFound for an unknown id).
func (s *Service) DeviceAuthorizationStatus(id string) (deviceflow.State, error) {
	if !s.Enabled() {
		return deviceflow.State{}, ErrDisabled
	}
	return s.device.Status(id)
}

// CancelDeviceAuthorization cancels an authorization (deviceflow.ErrNotFound
// for an unknown id).
func (s *Service) CancelDeviceAuthorization(ctx context.Context, id string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	return s.device.Cancel(ctx, id)
}
