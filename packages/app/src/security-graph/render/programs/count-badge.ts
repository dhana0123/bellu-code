// Count-badge node program: a small white circle with a thin border at the top-right.
// Set the `badge` node attribute to 1 when the node has collapsed children. The overlay
// draws the count text; WebGL draws only the disc. Hidden below the icon size threshold.
import type { FragmentLayer } from "sigma/rendering"
import { badgeCenter, badgeRadius, glslColor } from "./geometry"

export function badgeLayer(options: { fill: string; border: string; borderWidth: number; iconMinPixels: number }): FragmentLayer {
  return {
    name: "sgbadge",
    uniforms: [
      { name: "u_sgBadgeBorderPx", type: "float", value: options.borderWidth },
      { name: "u_sgIconMinPx", type: "float", value: options.iconMinPixels },
    ],
    attributes: [{ name: "a_badge", size: 1, type: 0x1406, source: "badge", defaultValue: 0 }],
    glsl: `
vec4 layer_sgbadge(float v_badge, float u_sgBadgeBorderPx, float u_sgIconMinPx) {
  if (v_badge < 0.5) return vec4(0.0);
  float d = length(context.uv - vec2(${badgeCenter.toFixed(3)}) * context.shapeSize) - ${badgeRadius.toFixed(3)} * context.shapeSize;
  float lod = smoothstep(u_sgIconMinPx * 0.85, u_sgIconMinPx, context.pixelSize);
  float outer = smoothstep(context.aaWidth, -context.aaWidth, d);
  float inner = smoothstep(context.aaWidth, -context.aaWidth, d + u_sgBadgeBorderPx * context.pixelToUV);
  vec4 color = mix(${glslColor(options.border)}, ${glslColor(options.fill)}, inner);
  return vec4(color.rgb, color.a * outer * lod);
}
`,
  }
}
