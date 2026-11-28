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
  security_overview: "Enable the Security Overview page with the nine Category cards and the category summary endpoint.",
  security_findings: "Enable the unified Finding model, Finding_Store, and the real Findings page backed by it.",
  security_scanners:
    "Enable embedded SBOM, vulnerability, misconfiguration and secret scanning and the Scanners page.",
  security_posture: "Enable the Policy_Engine, bundled Rule_Packs, Issues as Toxic_Combinations, and the Issues page.",
  security_cve_graph: "Enable Graph_Mode and Both_Mode for the CVE_Source against a configured BSKG server.",
  security_multicloud: "Enable the GCP, Azure and Kubernetes collectors and their schema leaves.",
  security_runtime:
    "Enable the Runtime_Sensor ingest endpoint, runtime rules, and the Runtime category card's live counts.",
  security_ai: "Enable the AI security inventory (aischema), AI-BOM, and the AI security category card.",
} as const satisfies Record<string, string>
export type Key = keyof typeof registry
