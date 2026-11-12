---
name: security-context
description: How to query the bellu-graph infrastructure graph for security questions, which MCP tools exist, and the rule to never request secret values.
---

# Security context from the infrastructure graph

Use the `bellu-graph` MCP server to answer security questions about the
infrastructure topology: what exists, what connects to what, what changed, and
what would be affected if something failed.

## How to query

1. Start with `describe_schema` to see which entity and relation types exist.
2. Use `describe_type` to zoom in on one type.
3. Locate entities with `find_entities`, then fetch one with `get_entity`.
4. Explore connections with `get_neighbors` and `find_path`.
5. Assess blast radius with `impact_of`.
6. Investigate change with `entity_history`, `recent_changes` and `graph_diff`.
7. Use `telemetry_keys` to get the keys that locate an entity's metrics and logs.
8. Use `annotate_entity` only when the user asks you to record a note (owner,
   runbook, ticket). It is an audited write.

## Tools

- `describe_schema`
- `describe_type`
- `find_entities`
- `get_entity`
- `annotate_entity`
- `get_neighbors`
- `find_path`
- `impact_of`
- `entity_history`
- `recent_changes`
- `graph_diff`
- `telemetry_keys`

## Secrets

Never request, read, print or store secret values: passwords, tokens, API keys,
private keys or credentials. If a user pastes one, do not repeat it. Refer to
secrets by name or location only, and ask the user to rotate any that were
exposed.
