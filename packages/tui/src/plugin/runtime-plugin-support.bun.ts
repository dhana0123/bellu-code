import { ensurePluginRuntime, provides } from "@bellucode/plugin/runtime"
import { Plugin, PluginContextProvider, usePlugin } from "@bellucode/plugin/tui"
import { ensureRuntimePluginSupport } from "@opentui/solid/runtime-plugin-support/configure"

ensurePluginRuntime()
ensureRuntimePluginSupport({
  additional: {
    "@bellucode/plugin/tui": { Plugin, PluginContextProvider, usePlugin },
  },
  preserve: provides,
})
