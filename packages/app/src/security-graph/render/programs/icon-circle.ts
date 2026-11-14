// Icon-circle node program: a filled circle in the node color with an atlas icon centered.
// Below the icon size threshold it draws only the plain colored dot.
// Per-node inputs are node attributes (or style variables): color, iconCell, iconTint.
import type { FragmentLayer, SDFShape } from "sigma/rendering"
import type { Atlas, AtlasCanvas } from "../atlas"
import { atlasUnit, badgeCenter, badgeRadius, GL_FLOAT, GL_UNSIGNED_BYTE, mainRadius } from "./geometry"

// Circle plus an optional badge circle at the top-right. The badge area is part of the shape
// (so it is not clipped and is pickable) only when the `badge` attribute is set.
export const nodeShape: SDFShape = {
  name: "sgnode",
  glsl: `
float sdf_sgnode(vec2 uv, float size, float badge) {
  float d = length(uv) - size * ${mainRadius.toFixed(3)};
  if (badge > 0.5) d = min(d, length(uv - vec2(${badgeCenter.toFixed(3)}) * size) - ${badgeRadius.toFixed(3)} * size);
  return d;
}
`,
  uniforms: [],
  attributes: [{ name: "a_badge", size: 1, type: GL_FLOAT, source: "badge", defaultValue: 0 }],
}

export function dotLayer(): FragmentLayer {
  return {
    name: "sgdot",
    uniforms: [],
    attributes: [
      { name: "a_fillColor", size: 4, type: GL_UNSIGNED_BYTE, normalized: true, source: "color" },
    ],
    glsl: `
vec4 layer_sgdot(vec4 v_fillColor) {
  float d = length(context.uv) - context.shapeSize * ${mainRadius.toFixed(3)};
  return vec4(v_fillColor.rgb, v_fillColor.a * smoothstep(context.aaWidth, -context.aaWidth, d));
}
`,
  }
}

// iconMinPixels: node diameter in screen pixels at which icons start to fade in.
export function iconLayer(options: { atlas: Atlas; iconMinPixels: number }): FragmentLayer {
  return {
    name: "sgicon",
    uniforms: [
      { name: "u_sgAtlas", type: "sampler2D" },
      { name: "u_sgAtlasGrid", type: "vec2", value: [options.atlas.cols, options.atlas.rows] },
      { name: "u_sgIconMinPx", type: "float", value: options.iconMinPixels },
      { name: "u_sgIconHalf", type: "float", value: mainRadius * 0.62 },
    ],
    attributes: [
      { name: "a_iconCell", size: 1, type: GL_FLOAT, source: "iconCell", defaultValue: -1 },
      { name: "a_iconTint", size: 4, type: GL_UNSIGNED_BYTE, normalized: true, source: "iconTint" },
    ],
    // The texture is read before any early return so mipmap derivatives stay in uniform control flow.
    // Atlas texels are premultiplied.
    glsl: `
vec4 layer_sgicon(float v_iconCell, vec4 v_iconTint, sampler2D u_sgAtlas, vec2 u_sgAtlasGrid, float u_sgIconMinPx, float u_sgIconHalf) {
  float cell = floor(max(v_iconCell, 0.0) + 0.5);
  float row = floor(cell / u_sgAtlasGrid.x);
  float col = cell - row * u_sgAtlasGrid.x;
  vec2 p = context.uv / u_sgIconHalf;
  vec2 inCell = clamp(vec2(0.5 + 0.5 * p.x, 0.5 - 0.5 * p.y), 0.0, 1.0);
  vec4 s = texture(u_sgAtlas, (vec2(col, row) + inCell) / u_sgAtlasGrid);
  float lod = smoothstep(u_sgIconMinPx * 0.85, u_sgIconMinPx, context.pixelSize);
  if (v_iconCell < 0.0 || lod <= 0.0 || abs(p.x) > 1.0 || abs(p.y) > 1.0) return vec4(0.0);
  vec3 rgb = s.a > 0.0 ? s.rgb / s.a : vec3(0.0);
  rgb = mix(rgb, v_iconTint.rgb, v_iconTint.a);
  return vec4(rgb, s.a * lod);
}
`,
    lifecycle: (context) => {
      const gl = context.gl
      const texture = options.atlas.canvas ? upload(gl, options.atlas.canvas) : null
      return {
        beforeRender() {
          if (!texture) return
          gl.activeTexture(gl.TEXTURE0 + atlasUnit)
          gl.bindTexture(gl.TEXTURE_2D, texture)
          const location = context.getUniformLocation("u_sgAtlas")
          if (location) gl.uniform1i(location, atlasUnit)
          gl.activeTexture(gl.TEXTURE0)
        },
        kill() {
          if (texture) gl.deleteTexture(texture)
        },
      }
    },
  }
}

function upload(gl: WebGL2RenderingContext, canvas: AtlasCanvas) {
  const texture = gl.createTexture()
  gl.activeTexture(gl.TEXTURE0 + atlasUnit)
  gl.bindTexture(gl.TEXTURE_2D, texture)
  gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, true)
  gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, canvas)
  gl.pixelStorei(gl.UNPACK_PREMULTIPLY_ALPHA_WEBGL, false)
  gl.generateMipmap(gl.TEXTURE_2D)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE)
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE)
  gl.activeTexture(gl.TEXTURE0)
  return texture
}
