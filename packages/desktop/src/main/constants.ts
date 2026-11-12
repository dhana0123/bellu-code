import { app } from "electron"

type Channel = "local" | "dev" | "beta" | "prod"

const raw = import.meta.env.BELLUCODE_CHANNEL

export const CHANNEL: Channel = raw === "local" || raw === "dev" || raw === "beta" || raw === "prod" ? raw : "dev"

export const VERSION = app.isPackaged ? app.getVersion() : (process.env.BELLUCODE_VERSION ?? app.getVersion())

const appNames: Record<string, string> = {
  dev: "Bellu Code Dev",
  beta: "Bellu Code Beta",
  prod: "Bellu Code",
}

const appIDs: Record<string, string> = {
  dev: "ai.bellucode.desktop.dev",
  beta: "ai.bellucode.desktop.beta",
  prod: "ai.bellucode.desktop",
}

// Local renderer/server mode keeps the dev application identity.
export const APP_NAME = app.isPackaged ? appNames[CHANNEL] : "Bellu Code Dev"

export const APP_ID = app.isPackaged ? appIDs[CHANNEL] : "ai.bellucode.desktop.dev"
