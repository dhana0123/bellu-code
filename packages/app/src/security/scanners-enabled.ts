import { bomConfigFlag } from "./bom-enabled"

/** The `security_scanners` flag from config entries. The BOM page reads the same flag, so both resolve it one way. */
export const scannersConfigFlag = bomConfigFlag

/** Scanners is available when no config turns the flag off and the scanner list answers; a disabled service 404s. */
export function scannersAvailable(input: { flag: boolean | undefined; probe: { enabled: boolean } | undefined }) {
  return input.flag !== false && input.probe?.enabled === true
}
