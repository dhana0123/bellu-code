// Emits internal/auth/testdata/vectors.json from the real TS implementation.
// Run from packages/server: bun ../../services/bellud/script/gen-auth-vectors.ts
import path from "node:path"
import { ServerAuth } from "../../../packages/server/src/auth"

// effect is a dependency of packages/server, not of this script.
const { Option } = await import(Bun.resolveSync("effect", path.join(import.meta.dir, "../../../packages/server")))
const out = path.join(import.meta.dir, "../internal/auth/testdata/vectors.json")
const NOW = 1_700_000_000_000
const TTL_MS = ServerAuth.SESSION_TTL_SECONDS * 1000
const cfg = (password: string) => ({ password: Option.some(password), username: "bellucode" })

const passwords = ["hunter2", "pässwörd ✓", "a".repeat(200)]
const issue = (password: string, now: number) => ServerAuth.issueSession(cfg(password), now)!

// Tokens issued by TS. Go must reproduce each token byte for byte (HMAC is deterministic),
// which also proves TS verifies Go-issued tokens for the same (password, now).
const issued = passwords.flatMap((password) =>
  [NOW, NOW + 999, 0, 86_400_000].map((now) => ({ password, now, token: issue(password, now) })),
)

const verify = (name: string, password: string, now: number, token: string) => ({
  name,
  password,
  now,
  token,
  expected: ServerAuth.verifySession(token, cfg(password), now),
})

const cases = passwords.flatMap((password) => {
  const token = issue(password, NOW)
  const expiry = NOW + TTL_MS
  const [exp, sig] = token.split(".")
  const flipped = sig.slice(0, -1) + (sig.endsWith("A") ? "B" : "A")
  const other = issue(password + "x", NOW)
  return [
    verify("valid at issue time", password, NOW, token),
    verify("valid just before expiry", password, expiry - 1, token),
    verify("rejected at expiry boundary", password, expiry, token),
    verify("rejected after expiry", password, expiry + 1, token),
    verify("rejected tampered signature", password, NOW, `${exp}.${flipped}`),
    verify("rejected truncated signature", password, NOW, `${exp}.${sig.slice(0, -2)}`),
    verify("rejected extended expiry", password, NOW, `${Number(exp) + 1}.${sig}`),
    verify("rejected token from other password", password, NOW, other),
    verify("rejected empty token", password, NOW, ""),
    verify("rejected no separator", password, NOW, exp),
    verify("rejected extra segment", password, NOW, `${token}.x`),
    verify("rejected empty signature", password, NOW, `${exp}.`),
    verify("rejected empty expiry", password, NOW, `.${sig}`),
    verify("rejected non-numeric expiry", password, NOW, `abc.${sig}`),
    verify("rejected negative expiry", password, NOW, `-1.${sig}`),
    verify("rejected fractional expiry", password, NOW, `${exp}.5.${sig}`),
    verify("rejected unsafe integer expiry", password, NOW, `9007199254740993.${sig}`),
    verify("rejected password as token", password, NOW, password),
  ]
})

const sanity = cases.filter((c) => c.expected).map((c) => c.name)
if (sanity.length !== passwords.length * 2) throw new Error(`unexpected accepted cases: ${sanity.join(", ")}`)

await Bun.write(
  out,
  JSON.stringify(
    {
      generatedBy: "services/bellud/script/gen-auth-vectors.ts (packages/server/src/auth.ts)",
      // Behaviour that intentionally differs; no vectors are emitted for these.
      excluded: [
        "empty password: TS signs/accepts tokens with an empty key, Go rejects everything",
        "non-decimal expiry such as 1e12, 0x.., +N, leading zeros, whitespace: TS uses Number(), Go uses strict decimal parsing",
      ],
      issued,
      cases,
    },
    null,
    2,
  ) + "\n",
)
console.log(`wrote ${out}: ${issued.length} issued, ${cases.length} cases`)
