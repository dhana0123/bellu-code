import type { SbomPackage, SbomSummary } from "@bellucode/client/promise"
// Lifecycle of the SBOM tab. Every request carries an attempt id, and a result for another attempt changes nothing.
export type AssetsState =
  | { type: "loading"; attempt: number }
  | { type: "ready"; attempt: number; assets: readonly SbomSummary[] }
  /** `unavailable` means the server does not serve the SBOM API. */
  | { type: "failed"; attempt: number; reason: "unavailable" | "error" }
  | { type: "disposed" }
export type AssetsEvent =
  | { type: "refresh" }
  | { type: "loaded"; attempt: number; assets: readonly SbomSummary[] }
  | { type: "failed"; attempt: number; reason: "unavailable" | "error" }
  | { type: "disposed" }
export const assetsInitial: AssetsState = { type: "loading", attempt: 1 }
export function assetsTransition(state: AssetsState, event: AssetsEvent): AssetsState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return { type: "disposed" }
  if (event.type === "refresh") return state.type === "loading" ? state : { type: "loading", attempt: state.attempt + 1 }
  if (state.type !== "loading" || state.attempt !== event.attempt) return state
  if (event.type === "failed") return { type: "failed", attempt: state.attempt, reason: event.reason }
  return { type: "ready", attempt: state.attempt, assets: event.assets }
}
type Packages = readonly SbomPackage[]
export type PackagesState =
  | { type: "idle"; attempt: number }
  | { type: "loading"; attempt: number; assetId: string; packages: Packages; cursor?: string }
  | { type: "ready"; attempt: number; assetId: string; packages: Packages; next?: string }
  | { type: "failed"; attempt: number; assetId: string; packages: Packages; cursor?: string }
  | { type: "disposed" }
export type PackagesEvent =
  | { type: "select"; assetId: string | undefined }
  | { type: "more" }
  | { type: "retry" }
  | { type: "loaded"; attempt: number; packages: Packages; next?: string }
  | { type: "failed"; attempt: number }
  | { type: "disposed" }
export const packagesInitial: PackagesState = { type: "idle", attempt: 0 }
export function packagesTransition(state: PackagesState, event: PackagesEvent): PackagesState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return { type: "disposed" }
  if (event.type === "select") {
    if (event.assetId === undefined) return state.type === "idle" ? state : { type: "idle", attempt: state.attempt + 1 }
    if (state.type !== "idle" && state.assetId === event.assetId) return state
    return { type: "loading", attempt: state.attempt + 1, assetId: event.assetId, packages: [] }
  }
  if (event.type === "more") {
    if (state.type !== "ready" || state.next === undefined) return state
    return { type: "loading", attempt: state.attempt + 1, assetId: state.assetId, packages: state.packages, cursor: state.next }
  }
  if (event.type === "retry") {
    if (state.type !== "failed") return state
    return { type: "loading", attempt: state.attempt + 1, assetId: state.assetId, packages: state.packages, cursor: state.cursor }
  }
  if (state.type !== "loading" || state.attempt !== event.attempt) return state
  if (event.type === "failed")
    return { type: "failed", attempt: state.attempt, assetId: state.assetId, packages: state.packages, cursor: state.cursor }
  return {
    type: "ready",
    attempt: state.attempt,
    assetId: state.assetId,
    packages: state.cursor === undefined ? event.packages : [...state.packages, ...event.packages],
    next: event.next,
  }
}
export const selectedAsset = (state: PackagesState) =>
  state.type === "idle" || state.type === "disposed" ? undefined : state.assetId
const NONE: Packages = []
export const selectPackages = (state: PackagesState) =>
  state.type === "idle" || state.type === "disposed" ? NONE : state.packages
export const selectFirstLoad = (state: PackagesState) => state.type === "loading" && state.cursor === undefined
export const selectLoadingMore = (state: PackagesState) => state.type === "loading" && state.cursor !== undefined
export const selectHasMore = (state: PackagesState) => state.type === "ready" && state.next !== undefined
// Lifecycle of one download. A second request while one runs changes nothing.
export type ExportState =
  | { type: "idle"; attempt: number }
  | { type: "exporting"; attempt: number }
  | { type: "failed"; attempt: number }
  | { type: "disposed" }
export type ExportEvent =
  | { type: "start" }
  | { type: "done"; attempt: number }
  | { type: "failed"; attempt: number }
  | { type: "disposed" }
export const exportInitial: ExportState = { type: "idle", attempt: 0 }
export function exportTransition(state: ExportState, event: ExportEvent): ExportState {
  if (state.type === "disposed") return state
  if (event.type === "disposed") return { type: "disposed" }
  if (event.type === "start") return state.type === "exporting" ? state : { type: "exporting", attempt: state.attempt + 1 }
  if (state.type !== "exporting" || state.attempt !== event.attempt) return state
  return event.type === "done" ? { type: "idle", attempt: state.attempt } : { type: "failed", attempt: state.attempt }
}
