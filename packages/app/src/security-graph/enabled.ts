type ConfigEntries = ReadonlyArray<{
  type: string
  info?: { experimental?: { security_graph?: boolean; all_flags?: boolean } }
}>

/**
 * The TS side of the `security_graph` flag from config entries. The highest-priority document that sets
 * `experimental` decides `experimental.security_graph`, then `all_flags: true`. The app cannot call Core's
 * `Flag.enabled`, so a flag that no config sets is `undefined` (the build default and `BELLUCODE_FLAGS` are not
 * visible here).
 */
export function securityGraphConfigFlag(entries: ConfigEntries | undefined): boolean | undefined {
  if (!entries) return undefined
  const documents = entries.flatMap((entry) =>
    entry.type === "document" && entry.info?.experimental ? [entry.info.experimental] : [],
  )
  const configured = documents.at(-1)?.security_graph
  if (configured !== undefined) return configured
  return documents.some((item) => item.all_flags === true) ? true : undefined
}

/** The Security Graph route and nav entry register only when the flag is explicitly on. */
export function securityGraphEnabled(entries: ConfigEntries | undefined) {
  return securityGraphConfigFlag(entries) === true
}
