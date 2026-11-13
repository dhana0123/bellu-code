import { describe, expect, test } from "bun:test"
import {
  INITIAL_GITHUB_STATE,
  selectClassicRejected,
  selectPrefixHint,
  selectRepositoriesRequired,
  selectSaveDisabled,
  transitionGithub,
  type GithubEvent,
} from "./github-machine"

const run = (events: readonly GithubEvent[]) => events.reduce(transitionGithub, INITIAL_GITHUB_STATE)
const repo = (fullName: string) => ({ fullName, private: false })
const loaded = [
  { type: "connection.created", connectionId: "c1" },
  { type: "repos.loaded", attempt: 1, items: [repo("a/b"), repo("a/c")] },
] as const

describe("github panel machine", () => {
  test("prefix hint only for a non-empty token without the prefix", () => {
    expect([selectPrefixHint(""), selectPrefixHint("ghp_x"), selectPrefixHint("github_pat_x")]).toEqual([
      false,
      true,
      false,
    ])
  })

  test("required message is hidden on the initial empty list and shows after a selection empties it", () => {
    const initial = run(loaded)
    expect(selectSaveDisabled(initial)).toBe(true)
    expect(selectRepositoriesRequired(initial)).toBe(false)

    const selected = run([...loaded, { type: "repo.toggled", fullName: "a/b" }])
    expect(selectSaveDisabled(selected)).toBe(false)

    const emptied = run([...loaded, { type: "repo.toggled", fullName: "a/b" }, { type: "repo.toggled", fullName: "a/b" }])
    expect(selectSaveDisabled(emptied)).toBe(true)
    expect(selectRepositoriesRequired(emptied)).toBe(true)
  })

  test("a stale list answer is ignored after a retry", () => {
    const retried = run([
      { type: "connection.created", connectionId: "c1" },
      { type: "repos.failed", attempt: 1 },
      { type: "repos.retried" },
      { type: "repos.loaded", attempt: 1, items: [repo("a/b")] },
    ])
    expect(retried.status === "repositories" && retried.repos.phase).toBe("loading")
  })

  test("selection is ignored until the list is ready", () => {
    const state = run([
      { type: "connection.created", connectionId: "c1" },
      { type: "repo.toggled", fullName: "a/b" },
    ])
    expect(state.status === "repositories" && state.touched).toBe(false)
  })

  test("classic submission is remembered until a prefixed token is submitted", () => {
    const classic = run([{ type: "credentials.submitted", classic: true }])
    expect(selectClassicRejected(classic)).toBe(true)
    expect(selectClassicRejected(transitionGithub(classic, { type: "credentials.submitted", classic: false }))).toBe(
      false,
    )
  })
})
