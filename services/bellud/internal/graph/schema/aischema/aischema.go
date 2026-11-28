// Package aischema declares the kinds and relations of the AI inventory
// source: models, agents, tools, MCP servers, vector stores and AI services.
// It imports only the standard library and schema.
//
// Identity is (connection, id). Cloud items use the provider resource id.
// Repository items use an id derived from (repo, path, name), and also store
// repo, path and name as plain attributes.
package aischema

import "github.com/bellu/bellucode/services/bellud/internal/graph/schema"

// CatAI is the collection category of AI assets. It differs from the Azure
// category azure_ai.
const CatAI = "ai_assets"

// Kind names.
const (
	KindModel       = "ai_model"
	KindAgent       = "ai_agent"
	KindTool        = "ai_tool"
	KindMCPServer   = "mcp_server"
	KindVectorStore = "vector_store"
	KindService     = "ai_service"
)

// Relation names.
const (
	RelRunsIn         = "ai_runs_in"
	RelUsesIdentity   = "ai_uses_identity"
	RelHasTool        = "ai_has_tool"
	RelReadsInputFrom = "ai_reads_input_from"
	RelServes         = "ai_serves"
)

func kind(name, desc string) schema.KindDeclaration {
	return schema.KindDeclaration{Name: name, Identity: []string{"connection", "id"}, Overview: schema.OvAI, Description: desc}
}

func rel(name string, d schema.Direction, desc string, from, to []string) schema.RelationDeclaration {
	return schema.RelationDeclaration{Name: name, Direction: d, Confidence: schema.Extracted, Description: desc, From: from, To: to, Category: CatAI}
}

// Declaration returns the AI inventory source declaration.
func Declaration() schema.SourceDeclaration {
	all := []string{KindModel, KindAgent, KindTool, KindMCPServer, KindVectorStore, KindService}
	return schema.SourceDeclaration{
		Source: schema.SourceAI,
		Kinds: []schema.KindDeclaration{
			kind(KindModel, "An AI model that a cloud service hosts or a repository references."),
			kind(KindAgent, "An AI agent that calls models and tools."),
			kind(KindTool, "A tool that an agent can call."),
			kind(KindMCPServer, "A Model Context Protocol server that exposes tools."),
			kind(KindVectorStore, "A vector store that holds embeddings for retrieval."),
			kind(KindService, "A managed AI service, such as a model endpoint or an ML workspace."),
		},
		Categories: []schema.CategoryDeclaration{
			{ID: CatAI, Name: "AI assets", Status: schema.Implemented},
		},
		Relations: []schema.RelationDeclaration{
			rel(RelRunsIn, schema.Forward, "The AI asset runs in the resource, so the resource's exposure applies to it.", all, nil),
			rel(RelUsesIdentity, schema.Forward, "Compromise of the AI asset yields the permissions of the identity.", all, nil),
			rel(RelHasTool, schema.Forward, "The agent can call the tool or MCP server.", []string{KindAgent}, []string{KindTool, KindMCPServer}),
			rel(RelReadsInputFrom, schema.Forward, "The AI asset reads input from the data source, so poisoned data can steer it.", all, nil),
			rel(RelServes, schema.Forward, "The service serves the model or agent.", []string{KindService}, []string{KindModel, KindAgent}),
		},
	}
}
