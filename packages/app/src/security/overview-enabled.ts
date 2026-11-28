type ConfigEntries = ReadonlyArray<{
  type: string
  info?: { experimental?: { security_overview?: boolean; all_flags?: boolean } }
}>

/**
 * The TS side of the `security_overview` flag from config entries, resolved like `connectorsConfigFlag`: the
 * highest-priority document that sets `experimental` decides, then `all_flags: true`. A flag no config sets is
 * `undefined` (the build default and `BELLUCODE_FLAGS` are not visible here), which leaves the decision to the probe.
 */
export function overviewConfigFlag(entries: ConfigEntries | undefined): boolean | undefined {
  if (!entries) return undefined
  const documents = entries.flatMap((entry) =>
    entry.type === "document" && entry.info?.experimental ? [entry.info.experimental] : [],
  )
  const configured = documents.at(-1)?.security_overview
  if (configured !== undefined) return configured
  return documents.some((item) => item.all_flags === true) ? true : undefined
}

/** Overview is available when no config turns the flag off and the summary endpoint answers; a disabled one 404s. */
export function overviewAvailable(input: { flag: boolean | undefined; probe: { enabled: boolean } | undefined }) {
  return input.flag !== false && input.probe?.enabled === true
}
