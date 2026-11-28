import { ClientError } from "@bellucode/client/promise"
import type {
  ExperimentalFindingsGetOutput,
  ExperimentalFindingsListInput,
  ExperimentalFindingsListOutput,
} from "@bellucode/client/promise"
import {
  SERVER_SORT,
  type FilterState,
  type Finding,
  type SortState,
  type StatusEvent,
} from "./model"

/** The most the server returns in one page. Fewer round trips for a long list. */
export const PAGE_LIMIT = 500

type Item = ExperimentalFindingsListOutput["items"][number]

/**
 * Maps the page filters and sort to the list request. The search box, which the API has no parameter for, is not
 * sent and filters the loaded rows instead. A sort the server has no field for is not sent either.
 */
export function toListInput(filters: FilterState, sort: SortState, cursor?: string): ExperimentalFindingsListInput {
  const server = sort ? SERVER_SORT[sort.key] : undefined
  return {
    severity: filters.severity === "all" ? undefined : [filters.severity],
    type: filters.types.length > 0 ? filters.types : undefined,
    status: filters.statuses.length > 0 ? filters.statuses : undefined,
    category: filters.categories.length > 0 ? filters.categories : undefined,
    asset: filters.asset ? [filters.asset] : undefined,
    sort: server && sort?.dir === "desc" ? `-${server}` : server,
    limit: PAGE_LIMIT,
    cursor,
  }
}

export function toFinding(item: Item | ExperimentalFindingsGetOutput): Finding {
  return {
    id: item.id,
    ruleId: item.ruleId,
    title: item.title,
    description: item.description,
    category: item.category,
    type: item.type,
    severity: item.severity,
    status: item.status,
    assetId: item.assetId,
    source: item.source,
    firstSeen: item.firstSeen,
    lastSeen: item.lastSeen,
    occurrences: item.occurrences,
    // The schema also encodes non-finite numbers as strings. Only a real number is a score.
    riskScore: typeof item.riskScore === "number" ? item.riskScore : undefined,
    evidence: item.evidence.map((entry) => ({
      kind: entry.kind,
      ref: entry.ref,
      line: entry.line,
      excerpt: entry.excerpt,
    })),
    searchText: `${item.title} ${item.ruleId} ${item.assetId} ${item.source}`.toLowerCase(),
  }
}

export function toEvents(detail: ExperimentalFindingsGetOutput): StatusEvent[] {
  return detail.events.map((event) => ({
    seq: event.seq,
    at: event.at,
    actor: event.actor,
    prevStatus: event.prevStatus,
    newStatus: event.newStatus,
    reason: event.reason,
  }))
}

/**
 * Sorts a failure into the two the page tells apart. A 404, or a declared NotFoundError, means the server does not
 * serve the findings API (the flag is off). Everything else is an error the user can retry.
 */
export function failureReason(error: unknown): "unavailable" | "error" {
  if (error instanceof ClientError) {
    const cause = error.cause
    return error.reason === "UnexpectedStatus" && typeof cause === "object" && cause !== null && "status" in cause && cause.status === 404
      ? "unavailable"
      : "error"
  }
  return typeof error === "object" && error !== null && "_tag" in error && error._tag === "NotFoundError"
    ? "unavailable"
    : "error"
}

/** A 400 names the offending parameter. A 409 or any other failure has only a message. */
export function rejection(error: unknown): { field?: string; message: string } {
  if (typeof error === "object" && error !== null && "message" in error && typeof error.message === "string")
    return {
      field: "field" in error && typeof error.field === "string" ? error.field : undefined,
      message: error.message,
    }
  return { message: "" }
}
