export * as ConfigFlag from "./flag.js"

/** The `BELLUCODE_FLAGS` entry that turns every flag on, as in `all,-media_blob`. It is not a flag key. */
export const wildcard = "all"

/**
 * Every feature flag, by key, with what it turns on. A flag is on in local and dev builds and off in released ones;
 * `experimental.<key>` in config and `BELLUCODE_FLAGS` override that, and `BELLUCODE_FLAGS=all` or
 * `experimental.all_flags: true` turn every flag on. Read one with Core's `Flag.enabled("<key>")`.
 */
export const registry = {
  todo: "Enable the experimental todowrite tool.",
  background_compaction:
    "Enable experimental background compaction: summarize the conversation in the background as it nears the compaction threshold, so automatic compaction does not wait for the summary. Background summaries that are never used still cost tokens.",
  media_blob: "Store new session media once in a deduplicated blob table instead of inline in every message row.",
  schedules: "Enable experimental scheduled tasks that wake a session with a prompt.",
  artifacts: "Enable experimental artifacts backed by pluggable providers.",
  codemode_vm: "Run the Code Mode execute tool on the experimental bytecode VM instead of the legacy interpreter.",
  bellu_graph:
    "Enable the experimental Bellu Graph code-security integration: the bellu-graph MCP server entry, the security agent and the security-context skill.",
  connectors:
    "Enable the experimental Settings → Connectors page and the bellud connector service that connects AWS and GitHub read-only and feeds their metadata into the Bellu Graph.",
  seek_planner:
    "Enable the experimental seek subagent: a CWE planner and evidence selector that builds a Security_Context from the bellu-graph seek_retrieve tool.",
} as const satisfies Record<string, string>
export type Key = keyof typeof registry
