type ConfigEntries = ReadonlyArray<{
  type: string
  info?: { experimental?: { security_scanners?: boolean; all_flags?: boolean } }
}>
/**
 * The TS side of the `security_scanners` flag from config entries, resolved like `overviewConfigFlag`: the
 * highest-priority document that sets `experimental` decides, then `all_flags: true`. A flag no config sets is
 * `undefined`, which leaves the decision to the probe.
 */
export function bomConfigFlag(entries: ConfigEntries | undefined): boolean | undefined {
  if (!entries) return undefined
  const documents = entries.flatMap((entry) =>
    entry.type === "document" && entry.info?.experimental ? [entry.info.experimental] : [],
  )
  const configured = documents.at(-1)?.security_scanners
  if (configured !== undefined) return configured
  return documents.some((item) => item.all_flags === true) ? true : undefined
}
/** BOM is available when no config turns the flag off and the SBOM list answers; a disabled service 404s. */
export function bomAvailable(input: { flag: boolean | undefined; probe: { enabled: boolean } | undefined }) {
  return input.flag !== false && input.probe?.enabled === true
}
