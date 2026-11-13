import { describe, expect, test } from "bun:test"
import { ClientError } from "@bellucode/client"
import type { Connectors } from "@bellucode/schema/connectors"
import { createAuditState, transitionAudit, type AuditEffect, type AuditEvent, type AuditState } from "./audit-machine"
import { classifyConnectorFailure, failureMessage } from "./errors"
import {
  INITIAL_MUTATION_STATE,
  selectMutationBusy,
  transitionMutation,
  type MutationEvent,
  type MutationState,
} from "./mutation-machine"

// The client throws a declared error body as an Error whose fields stay on it.
const declared = (body: Record<string, unknown>) => Object.assign(new Error("server message"), body)
const unexpected = (status: number) =>
  new ClientError("UnexpectedStatus", { cause: { status }, detail: String(status) })

describe("classifyConnectorFailure", () => {
  test("keeps the code and offenders of a declared ConnectorError (400)", () => {
    const failure = classifyConnectorFailure(
      declared({ _tag: "ConnectorError", code: "excess_permission", offenders: ["s3:PutObject", "iam:*"] }),
      false,
    )
    expect(failure).toEqual({ kind: "connector", code: "excess_permission", offenders: ["s3:PutObject", "iam:*"] })
    expect(failureMessage(failure)).toEqual({
      key: "settings.connectors.error.excessPermission",
      params: { permissions: "s3:PutObject, iam:*" },
    })
  })

  test("names 403 and 413, which the client rejects without a body, by status", () => {
    expect(failureMessage(classifyConnectorFailure(unexpected(403), false)).key).toBe(
      "settings.connectors.error.authorization",
    )
    expect(failureMessage(classifyConnectorFailure(unexpected(413), false)).key).toBe(
      "settings.connectors.error.payloadTooLarge",
    )
  })

  test("maps conflict, unavailable, transport, timeout and unknown without echoing the server message", () => {
    expect(failureMessage(classifyConnectorFailure(declared({ _tag: "ConflictError" }), false)).key).toBe(
      "settings.connectors.error.syncInProgress",
    )
    expect(classifyConnectorFailure(declared({ _tag: "ServiceUnavailableError" }), false).kind).toBe("unavailable")
    expect(classifyConnectorFailure(new ClientError("Transport"), false).kind).toBe("unavailable")
    expect(classifyConnectorFailure(unexpected(500), false).kind).toBe("unknown")
    // The deadline wins over whatever the aborted request rejected with.
    expect(classifyConnectorFailure(new ClientError("Transport"), true).kind).toBe("timeout")
  })
})

describe("mutation machine", () => {
  const replay = (events: MutationEvent[], from: MutationState = INITIAL_MUTATION_STATE) =>
    events.reduce((state, event) => transitionMutation(state, event).state, from)

  test("claims on start and drops a second start, so a double click sends one request", () => {
    const first = transitionMutation(INITIAL_MUTATION_STATE, { type: "started" })
    expect(first.effects).toEqual([{ type: "run", attempt: 1, timeoutMs: 30_000 }])
    const second = transitionMutation(first.state, { type: "started" })
    expect(second.state).toBe(first.state)
    expect(second.effects).toEqual([])
  })

  test("ignores a result of a stale attempt after a retry", () => {
    const failed = replay([
      { type: "started" },
      { type: "failed", attempt: 1, failure: { kind: "timeout" } },
      { type: "started" },
    ])
    expect(failed).toEqual({ status: "running", issued: 2, attempt: 2 })
    expect(replay([{ type: "succeeded", attempt: 1 }], failed)).toBe(failed)
  })

  test("every exit leaves running: success, failure, dispose", () => {
    const running = replay([{ type: "started" }])
    expect(selectMutationBusy(replay([{ type: "succeeded", attempt: 1 }], running))).toBe(false)
    expect(replay([{ type: "failed", attempt: 1, failure: { kind: "unknown" } }], running).status).toBe("failed")
    const disposed = transitionMutation(running, { type: "disposed" })
    expect(disposed.effects).toEqual([{ type: "abort", attempt: 1 }])
    expect(replay([{ type: "started" }], disposed.state)).toEqual({ status: "disposed" })
  })
})

describe("audit machine", () => {
  const entry = (seq: number): Connectors.AuditEntry => ({
    seq,
    ts: "2026-01-01T00:00:00.000Z",
    connectionId: "c1",
    connectorId: "aws",
    event: "test",
    outcome: "success",
    actor: "user",
    prev: "",
  })
  const replay = (events: AuditEvent[], from: AuditState = createAuditState()) =>
    events.reduce<{ state: AuditState; effects: AuditEffect[] }>(
      (current, event) => {
        const result = transitionAudit(current.state, event)
        return { state: result.state, effects: [...current.effects, ...result.effects] }
      },
      { state: from, effects: [] },
    )

  test("pages by cursor until the last page, then stops requesting", () => {
    const result = replay([
      { type: "target.synced", id: "c1" },
      { type: "page.loaded", attempt: 1, page: { items: [entry(2)], nextCursor: "n1" } },
      { type: "page.requested" },
      { type: "page.loaded", attempt: 2, page: { items: [entry(1)] } },
      { type: "page.requested" },
    ])
    expect(result.effects.filter((effect) => effect.type === "run").map((effect) => effect.cursor)).toEqual([
      undefined,
      "n1",
    ])
    expect(result.state).toMatchObject({ status: "idle", items: [{ seq: 2 }, { seq: 1 }], loaded: true })
  })

  test("a failed page keeps the list and retries the same cursor", () => {
    const result = replay([
      { type: "target.synced", id: "c1" },
      { type: "page.loaded", attempt: 1, page: { items: [entry(2)], nextCursor: "n1" } },
      { type: "page.requested" },
      { type: "page.failed", attempt: 2, failure: { kind: "timeout" } },
      { type: "page.requested" },
    ])
    expect(result.state).toMatchObject({ status: "loading", items: [{ seq: 2 }], next: "n1" })
    expect(result.effects.at(-1)).toMatchObject({ type: "run", attempt: 3, cursor: "n1" })
  })

  test("another Connection aborts the page in flight and drops the previous list", () => {
    const result = replay([
      { type: "target.synced", id: "c1" },
      { type: "target.synced", id: "c2" },
      { type: "page.loaded", attempt: 1, page: { items: [entry(9)] } },
    ])
    expect(result.effects).toContainEqual({ type: "abort", attempt: 1 })
    expect(result.state).toMatchObject({ status: "loading", id: "c2", items: [] })
  })
})
