import { app } from "electron"
import type { Endpoint } from "@bellucode/client/service"
import { Context, Effect, FileSystem, Layer, Path } from "effect"
import { SidecarChanged } from "../../shared/ipc-rpc/events"
import { emitIpcEvent } from "../ipc-events"
import { getMainWindows } from "../windows"
import { BackgroundServiceMachine } from "./background-service-machine"
import { cleanStages } from "./cli-stages"
import { keptStages } from "./cli-version"
import { DesktopCli } from "./desktop-cli"
import { SidecarCredentials } from "./sidecar-credentials"
import { ensureBellud } from "./bellud-sidecar"

export * as BackgroundService from "./background-service"

export interface Interface {
  readonly connection: Effect.Effect<SidecarCredentials.Data>
  readonly reconnect: Effect.Effect<SidecarCredentials.Data>
}

export class Service extends Context.Service<Service, Interface>()("bellucode/desktop/BackgroundService") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const context = yield* Effect.context<FileSystem.FileSystem | Path.Path | DesktopCli.Service>()

    return Service.of(
      yield* BackgroundServiceMachine.make({
        probe,
        ensure: (mode) => ensure(mode).pipe(Effect.provide(context)),
        publish: (data) => {
          SidecarCredentials.set(data)
          // Every window moves its requests and event stream to the new origin, not only the one that reconnected.
          const event = new SidecarChanged({ url: data.url })
          getMainWindows().forEach((win) => emitIpcEvent(win.webContents, event))
        },
      }),
    )
  }),
)

// bellud is a child of this app launch and writes no registration file, so there is never an earlier service to adopt.
const probe = Effect.sync((): SidecarCredentials.Data | undefined => undefined)

const ensure = Effect.fn("BackgroundService.ensure")(function* (mode: BackgroundServiceMachine.ConnectMode) {
  const runFork = Effect.runForkWith(yield* Effect.context<FileSystem.FileSystem | Path.Path>())
  const setup = yield* prepare(mode)

  // `bellud` is the Sidecar_Server. It spawns the bundled bellucode-cli binary itself (--cli-bin), or bun + packages/cli
  // from source in development (--repo). One instance runs per app launch, so a reconnect reuses it while it is alive.
  yield* Effect.logInfo("starting bellud sidecar", { bellud: setup.cli.bellud, mode })
  const running = yield* Effect.tryPromise({
    try: () => ensureBellud(setup.cli.bellud, { cliBinary: setup.cli.binary, repo: setup.cli.repo }),
    // Keep the SidecarStartupError as is: its fixed message is what the startup failure page shows.
    catch: (error) => error,
  })

  const ready = yield* adopt(setup, running.endpoint)

  // Only packaged and isolated builds run a staged copy; any other binary sits in the source tree.
  // The staged bellucode-cli stays on disk while bellud runs it, so only the bundled stage is kept.
  if (mode === "initial" && (app.isPackaged || setup.isolated) && setup.cli.binary)
    runFork(
      cleanStages(setup.cli.binary, { keep: keptStages(setup.cli.version) }).pipe(
        Effect.catch((error) => Effect.logError("failed to clean staged v2 CLIs", { error })),
      ),
    )

  return ready.credentials
})

const prepare = Effect.fn("BackgroundService.prepare")(function* (_mode: BackgroundServiceMachine.ConnectMode) {
  const desktopCli = yield* DesktopCli.Service
  const isolated = !app.isPackaged && process.env.BELLUCODE_DESKTOP_ISOLATED_SERVER === "1"
  const cli = yield* desktopCli.resolve

  if (isolated) process.env.XDG_STATE_HOME = app.getPath("userData")

  return { cli, isolated }
})

const adopt = Effect.fn("BackgroundService.adopt")(function* (
  setup: Effect.Success<ReturnType<typeof prepare>>,
  service: Endpoint,
) {
  if (service.auth?.type !== "basic") throw new Error("bellud did not provide authentication")
  const url = new URL(service.url)

  yield* Effect.logInfo("bellud sidecar ready", { version: setup.cli.version, ...endpoint(url.origin) })

  return { credentials: { url: url.origin, password: service.auth.password } satisfies SidecarCredentials.Data }
})

function endpoint(url: string | undefined) {
  if (!url || !URL.canParse(url)) return {}
  const parsed = new URL(url)

  return { url, hostname: parsed.hostname, port: parsed.port }
}
