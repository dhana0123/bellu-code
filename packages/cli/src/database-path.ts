import path from "node:path"
import { BELLUCODE_CHANNEL } from "./version"

export function databasePath(data: string) {
  const filename =
    process.env.BELLUCODE_DB ??
    (["latest", "dev", "beta", "next", "prod"].includes(BELLUCODE_CHANNEL) ||
    process.env.BELLUCODE_DISABLE_CHANNEL_DB === "1" ||
    process.env.BELLUCODE_DISABLE_CHANNEL_DB === "true"
      ? "bellucode.db"
      : `bellucode-${BELLUCODE_CHANNEL.replace(/[^a-zA-Z0-9._-]/g, "-")}.db`)
  return filename === ":memory:" ? filename : path.resolve(data, filename)
}
