import { describe, expect, test } from "bun:test"
import { buildCredential, buildParams, canSubmit, toggleRegion, type AwsForm } from "./aws-form"

const base: AwsForm = {
  method: "assume_role",
  source: "ambient",
  roleArn: "arn:aws:iam::123456789012:role/Bellu",
  externalId: "BELLU-0123456789abcdef0123456789abcdef",
  regions: ["eu-west-1", "us-east-1"],
  accessKeyId: "",
  secretAccessKey: "",
  sessionToken: "",
}

describe("aws connect form", () => {
  test("requires at least one region", () => {
    expect(canSubmit(base)).toBe(true)
    expect(canSubmit({ ...base, regions: [] })).toBe(false)
  })

  test("AssumeRole with ambient source sends no credential and the external id", () => {
    expect(buildCredential(base)).toEqual({})
    expect(buildParams(base)).toEqual({
      regions: "eu-west-1,us-east-1",
      roleArn: base.roleArn,
      source: "ambient",
      externalId: base.externalId,
    })
  })

  test("static keys need both keys and send the optional token only when set", () => {
    const keys: AwsForm = { ...base, method: "static_keys", accessKeyId: "AKIA", secretAccessKey: "s" }
    expect(canSubmit({ ...keys, secretAccessKey: "" })).toBe(false)
    expect(buildCredential(keys)).toEqual({ access_key_id: "AKIA", secret_access_key: "s" })
    expect(buildCredential({ ...keys, sessionToken: "t" }).session_token).toBe("t")
    expect(buildParams(keys)).toEqual({ regions: "eu-west-1,us-east-1" })
  })

  test("toggleRegion adds and removes", () => {
    expect(toggleRegion(["a"], "b")).toEqual(["a", "b"])
    expect(toggleRegion(["a", "b"], "a")).toEqual(["b"])
  })
})
