import { Plugin } from "@bellucode/plugin/tui"
import { createMermaidCodeBlockRenderer } from "./markdown.js"
import { resolveBelluCodeDiagramPalette } from "./palette.js"

export default Plugin.define({
  id: "bellucode.merman",
  setup(context) {
    context.markdown.registerCodeBlockRenderer(
      "mermaid",
      createMermaidCodeBlockRenderer(context.renderer, () => ({
        colors: resolveBelluCodeDiagramPalette(context.theme, context.themeMode),
      })),
    )
  },
})
