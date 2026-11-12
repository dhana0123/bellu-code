import { Option, Schema } from "effect"

declare const BELLUCODE_VERSION: string
declare const BELLUCODE_CHANNEL: string
declare const BELLUCODE_ARTIFACT: string
declare const BELLUCODE_RELEASE_HIGHLIGHTS: string

const version = typeof BELLUCODE_VERSION === "string" ? BELLUCODE_VERSION : "local"
const channel = typeof BELLUCODE_CHANNEL === "string" ? BELLUCODE_CHANNEL : "local"
const artifact = typeof BELLUCODE_ARTIFACT === "string" ? BELLUCODE_ARTIFACT : "cli"
// Stable release builds embed the release notes' Highlights; every other build has none.
const highlights =
  typeof BELLUCODE_RELEASE_HIGHLIGHTS === "string"
    ? Option.getOrElse(
        Schema.decodeUnknownOption(
          Schema.fromJsonString(Schema.Array(Schema.Struct({ title: Schema.String, body: Schema.String }))),
        )(BELLUCODE_RELEASE_HIGHLIGHTS),
        () => [],
      )
    : []

export {
  version as BELLUCODE_VERSION,
  channel as BELLUCODE_CHANNEL,
  artifact as BELLUCODE_ARTIFACT,
  highlights as BELLUCODE_HIGHLIGHTS,
}
export const BELLUCODE_LOCAL = channel === "local"
