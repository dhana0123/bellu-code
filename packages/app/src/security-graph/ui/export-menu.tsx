import { createSignal, For } from "solid-js"
import { Button } from "@bellucode/ui/button"
import { useTheme } from "@bellucode/ui/theme"
import { useLanguage } from "@/runtime/i18n/language"
import type { Driver } from "../driver"
import type { Renderer } from "../render/sigma"
import { download, exportJson, exportPng, exportSvg, renderGraphOf } from "./export"

type Format = "png" | "svg" | "json"
const formats = ["png", "svg", "json"] as const satisfies readonly Format[]

export type ExportMenuProps = {
  driver: Driver
  /** The element the renderer was created in. */
  container: () => HTMLElement | undefined
  renderer?: Pick<Renderer, "renderNow">
  filename?: string
}

export function ExportMenu(props: ExportMenuProps) {
  const language = useLanguage()
  const theme = useTheme()
  const [status, setStatus] = createSignal<"done" | "failed" | undefined>()
  const name = () => props.filename ?? "security-graph"

  async function run(format: Format) {
    setStatus(undefined)
    const result = await save(format).then(
      () => "done" as const,
      () => "failed" as const,
    )
    setStatus(result)
  }

  async function save(format: Format) {
    if (format === "png") {
      const container = props.container()
      if (!container) throw new Error("no container")
      return download(await exportPng(container, props.renderer), `${name()}.png`, "image/png")
    }
    const visible = props.driver.visible()
    if (format === "svg") return download(exportSvg(renderGraphOf(visible), theme.mode()), `${name()}.svg`, "image/svg+xml")
    return download(exportJson(visible), `${name()}.json`, "application/json")
  }

  return (
    <div class="flex items-center gap-1" role="group" aria-label={language.t("security.graph.exportMenu.label")}>
      <For each={formats}>
        {(format) => (
          <Button size="small" variant="ghost" onClick={() => void run(format)}>
            {language.t(`security.graph.export.${format}`)}
          </Button>
        )}
      </For>
      <span class="sr-only" role="status" aria-live="polite">
        {status() ? language.t(`security.graph.export.${status()!}`) : ""}
      </span>
    </div>
  )
}
