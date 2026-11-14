// Ring node program: a thin ring on the circle edge. External third-party nodes use it
// (white circle, grey ring). Per-node inputs: ringColor, ringWidth (screen pixels).
import type { FragmentLayer } from "sigma/rendering"
import { GL_FLOAT, GL_UNSIGNED_BYTE, mainRadius } from "./geometry"

export function ringLayer(): FragmentLayer {
  return {
    name: "sgring",
    uniforms: [],
    attributes: [
      { name: "a_ringColor", size: 4, type: GL_UNSIGNED_BYTE, normalized: true, source: "ringColor" },
      { name: "a_ringWidth", size: 1, type: GL_FLOAT, source: "ringWidth", defaultValue: 0 },
    ],
    glsl: `
vec4 layer_sgring(vec4 v_ringColor, float v_ringWidth) {
  if (v_ringWidth <= 0.0 || v_ringColor.a <= 0.0) return vec4(0.0);
  float d = length(context.uv) - context.shapeSize * ${mainRadius.toFixed(3)};
  float outer = smoothstep(context.aaWidth, -context.aaWidth, d);
  float inner = smoothstep(context.aaWidth, -context.aaWidth, d + v_ringWidth * context.pixelToUV);
  return vec4(v_ringColor.rgb, v_ringColor.a * outer * (1.0 - inner));
}
`,
  }
}
