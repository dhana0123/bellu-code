import { describe, expect, test } from "bun:test"
import { PROMPT_SEEK } from "@bellucode/core/plugin/seek-prompt"

const TOOL = "bellu-graph_seek_retrieve"

describe("PROMPT_SEEK contract", () => {
  test("states the JSON plan contract (R2.1, R2.2)", () => {
    expect(PROMPT_SEEK).toContain('"language"')
    expect(PROMPT_SEEK).toContain('"reasoning"')
    expect(PROMPT_SEEK).toContain('"weaknesses"')
    for (const field of ["cwe_id", "root_cause", "code_snippet"]) expect(PROMPT_SEEK).toContain(field)
  })

  test("states the cwe_id pattern (R2.3)", () => {
    expect(PROMPT_SEEK).toContain("^CWE-[0-9]{1,5}$")
  })

  test("states the weakness, root cause and snippet limits (R2.2, R2.3, R2.4)", () => {
    expect(PROMPT_SEEK).toMatch(/at most 20 weaknesses/i)
    expect(PROMPT_SEEK).toMatch(/1 to 1000 characters/)
    expect(PROMPT_SEEK).toMatch(/1 to 2000 characters/)
  })

  test("asks for distinct risks only, no broader or narrower variant of a predicted CWE (R2.2)", () => {
    expect(PROMPT_SEEK).toMatch(/distinct/i)
    expect(PROMPT_SEEK).toMatch(/broader or narrower variant/i)
  })
  test("tells the model to return an empty list and skip the tool when unsure (R2.2, R2.5)", () => {
    expect(PROMPT_SEEK).toMatch(/empty list/i)
    expect(PROMPT_SEEK).toMatch(/do not call the tool/i)
  })

  test("enforces the 2-Round limit (R7.4)", () => {
    expect(PROMPT_SEEK).toMatch(/at most 2 tool calls in total/i)
    expect(PROMPT_SEEK).toMatch(/fewer than 2 rounds/i)
  })

  test("states the 4000 and 6000 character output limits (R8.3)", () => {
    expect(PROMPT_SEEK).toMatch(/4000 characters/)
    expect(PROMPT_SEEK).toMatch(/6000/)
    expect(PROMPT_SEEK).toMatch(/top_k above 4/)
  })

  test("stops on cve_unavailable without another tool call (R10.3)", () => {
    const stop = PROMPT_SEEK.split("\n").find((line) => line.includes("cve_unavailable"))
    expect(stop).toBeDefined()
    expect(stop).toMatch(/stop/i)
    expect(stop).toMatch(/do not call the tool again/i)
  })

  test("has no language allowlist or language refusal wording (R2.7, R2.8)", () => {
    for (const pattern of [
      /allowlist/i,
      /allow-list/i,
      /whitelist/i,
      /supported languages?/i,
      /unsupported language/i,
      /only (supports?|works? with|handles?) /i,
      /languages? (is|are) not supported/i,
      /(refuse|decline|reject)[^.\n]*(unsupported|other|non-)[^.\n]*language/i,
    ])
      expect(PROMPT_SEEK).not.toMatch(pattern)
  })

  test("accepts any language, using unknown when undetermined (R2.7, R2.8)", () => {
    expect(PROMPT_SEEK).toMatch(/"unknown"/)
    expect(PROMPT_SEEK).toMatch(/never refuse a task because of its language/i)
  })

  test("names exactly one tool (R12.7)", () => {
    expect(PROMPT_SEEK).toContain(TOOL)
    expect(PROMPT_SEEK).toMatch(/exactly one tool/i)
    const names = new Set(PROMPT_SEEK.match(/\b[a-z0-9]+(?:-[a-z0-9]+)*_[a-z0-9_]+\b/g)?.filter((n) => n.includes("-")))
    expect([...names]).toEqual([TOOL])
  })
})
