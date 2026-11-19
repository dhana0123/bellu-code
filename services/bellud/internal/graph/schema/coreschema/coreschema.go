// Package coreschema declares the kinds and generic relation types that the
// core source owns. It imports only the standard library and schema.
package coreschema

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

// Kind names.
const (
	KindHost            = "host"
	KindProcess         = "process"
	KindListeningPort   = "listening_port"
	KindContainer       = "container"
	KindImage           = "image"
	KindNetwork         = "network"
	KindVolume          = "volume"
	KindRepository      = "repository"
	KindDependency      = "dependency"
	KindWorkflow        = "workflow"
	KindSecretRef       = "secret_ref"
	KindIacResource     = "iac_resource"
	KindK8sObject       = "k8s_object"
	KindSecretFinding   = "secret_finding"
	KindCollectorStatus = "collector_status"
	KindEndpoint        = "endpoint"
)

// Relation type names.
const (
	RelRunsOn     = "runs_on"
	RelOn         = "on"
	RelOwnedBy    = "owned_by"
	RelUses       = "uses"
	RelAttachedTo = "attached_to"
	RelMounts     = "mounts"
	RelDependsOn  = "depends_on"
	RelResolvesTo = "resolves_to"
	RelFoundIn    = "found_in"
)

func kind(name, desc string, identity ...string) schema.KindDeclaration {
	return schema.KindDeclaration{Name: name, Identity: identity, Description: desc}
}

func rel(name string, d schema.Direction, desc string) schema.RelationDeclaration {
	return schema.RelationDeclaration{Name: name, Direction: d, Confidence: schema.Extracted, Description: desc}
}

// Declaration returns the core source declaration.
func Declaration() schema.SourceDeclaration {
	return schema.SourceDeclaration{
		Source: schema.SourceCore,
		Kinds: []schema.KindDeclaration{
			kind(KindHost, "A machine or virtual machine.", "hostname"),
			kind(KindProcess, "A running process on a host.", "host", "pid", "start_time"),
			kind(KindListeningPort, "A socket that listens on a host.", "host", "protocol", "address", "port"),
			kind(KindContainer, "A container instance.", "id"),
			kind(KindImage, "A container image.", "id"),
			kind(KindNetwork, "A container or virtual network.", "id"),
			kind(KindVolume, "A storage volume.", "name"),
			kind(KindRepository, "A source repository on disk.", "path"),
			kind(KindDependency, "A dependency that a repository declares.", "repo", "name", "range"),
			kind(KindWorkflow, "A CI workflow file in a repository.", "repo", "path"),
			kind(KindSecretRef, "A reference to a secret by name. It holds no secret value.", "repo", "path", "name"),
			kind(KindIacResource, "A resource declared in infrastructure as code.", "path", "address"),
			kind(KindK8sObject, "A Kubernetes object.", "source", "kind", "namespace", "name"),
			kind(KindSecretFinding, "A location where a secret scanner found a possible secret.", "path", "line", "rule"),
			kind(KindCollectorStatus, "The run status of one collector.", "collector"),
			kind(KindEndpoint, "A network endpoint identified by protocol, address, and port.", "protocol", "address", "port"),
		},
		Relations: []schema.RelationDeclaration{
			rel(RelRunsOn, schema.Reverse, "From runs on to, so failure of to impacts from."),
			rel(RelOn, schema.Reverse, "From is located on to, so failure of to impacts from."),
			rel(RelOwnedBy, schema.Reverse, "From is owned by or contained in to, so failure of to impacts from."),
			rel(RelUses, schema.Reverse, "From uses to, so failure of to impacts from."),
			rel(RelAttachedTo, schema.Reverse, "From is attached to to, so failure of to impacts from."),
			rel(RelMounts, schema.Reverse, "From mounts to, so failure of to impacts from."),
			rel(RelDependsOn, schema.Reverse, "From depends on to, so failure of to impacts from."),
			rel(RelResolvesTo, schema.Reverse, "From resolves to to, so failure of to impacts from."),
			rel(RelFoundIn, schema.Forward, "A finding is found in a location, and compromise of the finding gives reach over the location."),
		},
	}
}
