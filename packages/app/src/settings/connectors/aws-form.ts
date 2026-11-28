import type { Connectors } from "@bellucode/schema/connectors"

export type AwsMethod = "assume_role" | "static_keys"
export type AwsSource = "ambient" | "vault"

/** Region codes are identifiers, not copy. The service validates the selection against its own host allowlist. */
export const AWS_REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "ca-central-1",
  "eu-west-1",
  "eu-west-2",
  "eu-west-3",
  "eu-central-1",
  "eu-north-1",
  "ap-south-1",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-northeast-1",
  "ap-northeast-2",
  "sa-east-1",
] as const

export const ROTATION_REMINDER_DAYS = 90

export type AwsForm = {
  readonly method: AwsMethod
  readonly source: AwsSource
  readonly roleArn: string
  readonly externalId: string
  readonly regions: readonly string[]
  readonly accessKeyId: string
  readonly secretAccessKey: string
  readonly sessionToken: string
}

/** Static keys, or an AssumeRole whose base credentials come from the vault, need access keys. */
export function needsKeys(form: Pick<AwsForm, "method" | "source">) {
  return form.method === "static_keys" || form.source === "vault"
}

/** The user sees the missing-region message only after interacting with the selection, so this is a plain predicate. */
export function regionsValid(regions: readonly string[]) {
  return regions.length >= 1
}

/** Whether Connect can be pressed. The service still validates every field. */
export function canSubmit(form: AwsForm) {
  if (!regionsValid(form.regions)) return false
  if (form.method === "assume_role" && (form.roleArn.trim() === "" || form.externalId === "")) return false
  if (needsKeys(form)) return form.accessKeyId.trim() !== "" && form.secretAccessKey !== ""
  return true
}

/** The credential map for the service: keys only when the method needs them. */
export function buildCredential(form: AwsForm): Connectors.CredentialInput {
  if (!needsKeys(form)) return {}
  const base = { access_key_id: form.accessKeyId.trim(), secret_access_key: form.secretAccessKey }
  return form.sessionToken === "" ? base : { ...base, session_token: form.sessionToken }
}

/** Non-secret params. `externalId` is sent for AssumeRole so the role trust policy and every AssumeRole call match. */
export function buildParams(form: AwsForm): Record<string, string> {
  const regions = form.regions.join(",")
  if (form.method === "static_keys") return { regions }
  return { regions, roleArn: form.roleArn.trim(), source: form.source, externalId: form.externalId }
}

export function toggleRegion(regions: readonly string[], region: string) {
  return regions.includes(region) ? regions.filter((item) => item !== region) : [...regions, region]
}
