// Arrowhead edge program: a thin line with a small arrowhead at the target.
// Styles: path "line" (default) or "curved" with a small `curvature`, head "arrow", size from sizes.edgeWidth.
import { extremityArrow, layerPlain, pathCurved, pathLine, type EdgeExtremity } from "sigma/rendering"
import { sizes } from "../../theme"

export function arrowEdgePrimitives() {
  return {
    paths: [pathLine(), pathCurved()],
    extremities: [
      extremityArrow({
        lengthRatio: sizes.arrowhead / sizes.edgeWidth,
        widthRatio: (sizes.arrowhead * 0.75) / sizes.edgeWidth,
      }),
    ] satisfies EdgeExtremity[],
    layers: [layerPlain()],
    defaultHead: "arrow",
    defaultTail: "none",
  }
}
