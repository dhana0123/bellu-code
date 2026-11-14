// Sigma 4 primitives for the security graph. Task 3.5 passes this as the `primitives` option.
//
// Node attributes read by the programs (set them as graph attributes or style variables):
//   color      node fill (built in)
//   iconCell   atlas cell index from `atlas.index(key)`, -1 for none
//   iconTint   optional rgba that replaces the icon color (for example grey on an external node)
//   ringColor, ringWidth   ring color and width in pixels (external-service nodes)
//   badge      1 draws the count badge disc at the top-right
// The node circle fills 80% of the node quad so the badge fits inside it.
import type { PrimitivesDeclaration } from "sigma/primitives"
import { palettes, sizes, zoom, type ThemeMode } from "../../theme"
import type { Atlas } from "../atlas"
import { arrowEdgePrimitives } from "./arrow-edge"
import { badgeLayer } from "./count-badge"
import { dotLayer, iconLayer, nodeShape } from "./icon-circle"
import { ringLayer } from "./ring"

export function securityGraphPrimitives(options: { atlas: Atlas; mode: ThemeMode }) {
  const palette = palettes[options.mode]
  // Icons appear once a node is as large as a default node at the icon zoom threshold.
  const iconMinPixels = sizes.node * zoom.iconThreshold
  return {
    nodes: {
      shapes: [nodeShape],
      variables: {
        iconCell: { type: "number", default: -1 },
        iconTint: { type: "color", default: "#00000000" },
        ringColor: { type: "color", default: "#00000000" },
        ringWidth: { type: "number", default: 0 },
        badge: { type: "number", default: 0 },
      },
      layers: [
        dotLayer(),
        iconLayer({ atlas: options.atlas, iconMinPixels }),
        ringLayer(),
        badgeLayer({
          fill: palette.externalFill,
          border: palette.externalRing,
          borderWidth: sizes.externalRingWidth,
          iconMinPixels,
        }),
      ],
    },
    edges: arrowEdgePrimitives(),
  } satisfies PrimitivesDeclaration
}
