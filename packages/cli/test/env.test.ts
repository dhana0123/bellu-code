import { expect, test } from "bun:test"
import { Env } from "../src/env"

test("session environment omits server credentials", () => {
  const previousPassword = process.env.BELLUCODE_PASSWORD
  const previousLegacyPassword = process.env.BELLUCODE_SERVER_PASSWORD
  const previousValue = process.env.BELLUCODE_SESSION_ENV_TEST
  process.env.BELLUCODE_PASSWORD = "password"
  process.env.BELLUCODE_SERVER_PASSWORD = "legacy"
  process.env.BELLUCODE_SESSION_ENV_TEST = "included"

  const environment = Env.session()

  if (previousPassword === undefined) delete process.env.BELLUCODE_PASSWORD
  else process.env.BELLUCODE_PASSWORD = previousPassword
  if (previousLegacyPassword === undefined) delete process.env.BELLUCODE_SERVER_PASSWORD
  else process.env.BELLUCODE_SERVER_PASSWORD = previousLegacyPassword
  if (previousValue === undefined) delete process.env.BELLUCODE_SESSION_ENV_TEST
  else process.env.BELLUCODE_SESSION_ENV_TEST = previousValue

  expect(environment.BELLUCODE_PASSWORD).toBeUndefined()
  expect(environment.BELLUCODE_SERVER_PASSWORD).toBeUndefined()
  expect(environment.BELLUCODE_SESSION_ENV_TEST).toBe("included")
})
