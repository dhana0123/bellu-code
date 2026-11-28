import { afterEach, beforeEach, expect, test } from "bun:test"
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { requiredResources, verifyResources } from "./verify-bundles"

let root: string
let resources: string

beforeEach(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "bellucode-verify-resources-"))
  resources = path.join(root, "resources")
  await mkdir(resources)
})

afterEach(() => rm(root, { recursive: true, force: true }))

async function put(names: string[]) {
  for (const name of names) await writeFile(path.join(resources, name), "binary")
}

async function failure(os: string) {
  const error = await verifyResources(resources, os).then(
    () => undefined,
    (error) => error as Error,
  )
  expect(error).toBeInstanceOf(Error)
  return error!.message
}

test("passes when all required resources are present", async () => {
  await put(["bellucode-cli", "bellud"])
  await verifyResources(resources, "linux")
})

test("fails naming the bellud path when bellud is missing", async () => {
  await put(["bellucode-cli"])
  const message = await failure("linux")
  expect(message).toContain(path.join(resources, "bellud"))
  expect(message).not.toContain(path.join(resources, "bellucode-cli"))
})

test("names both resources when both are missing", async () => {
  const message = await failure("linux")
  expect(message).toContain(path.join(resources, "bellud"))
  expect(message).toContain(path.join(resources, "bellucode-cli"))
})

test("treats an empty bellud file as missing", async () => {
  await put(["bellucode-cli"])
  await writeFile(path.join(resources, "bellud"), "")
  expect(await failure("linux")).toContain(path.join(resources, "bellud"))
})

test("win32 requires .exe names", async () => {
  expect(requiredResources("win32")).toEqual(["bellucode-cli.exe", "bellud.exe"])
  await put(["bellucode-cli", "bellud"])
  const message = await failure("win32")
  expect(message).toContain(path.join(resources, "bellud.exe"))
  expect(message).toContain(path.join(resources, "bellucode-cli.exe"))
  await put(["bellucode-cli.exe", "bellud.exe"])
  await verifyResources(resources, "win32")
})

test("a failing check leaves existing artifacts in dist untouched", async () => {
  const dist = path.join(root, "dist")
  await mkdir(dist)
  const artifact = path.join(dist, "BelluCode-1.0.0.AppImage")
  const content = Buffer.from([0, 1, 2, 3, 250, 251])
  await writeFile(artifact, content)
  await put(["bellucode-cli"])
  await failure("linux")
  expect(Buffer.compare(await readFile(artifact), content)).toBe(0)
})
