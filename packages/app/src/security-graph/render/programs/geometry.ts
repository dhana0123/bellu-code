// Shared by the node shape and every layer so they agree on where the circle and badge are.
// UV space is the node quad, [-1, 1], with +y pointing up on screen.
export const mainRadius = 0.8
export const badgeCenter = 0.72
export const badgeRadius = 0.28

// WebGL enum values, inlined so this module can load outside a browser.
export const GL_FLOAT = 0x1406
export const GL_UNSIGNED_BYTE = 0x1401

// Texture unit for the atlas. Sigma uses 0-7.
export const atlasUnit = 8

// Converts a theme CSS color (#rgb, #rrggbb, #rrggbbaa, rgb(a)) to a GLSL vec4 literal.
export function glslColor(css: string) {
  const value = css.trim()
  const channels = value.startsWith("#") ? hexChannels(value) : functionalChannels(value)
  return `vec4(${channels.map((channel) => channel.toFixed(4)).join(", ")})`
}

function hexChannels(value: string) {
  const hex = value.slice(1)
  const full = hex.length <= 4 ? [...hex].map((char) => char + char).join("") : hex
  const bytes = [0, 2, 4].map((at) => parseInt(full.slice(at, at + 2), 16) / 255)
  return [...bytes, full.length >= 8 ? parseInt(full.slice(6, 8), 16) / 255 : 1]
}

function functionalChannels(value: string) {
  const parts = value
    .slice(value.indexOf("(") + 1, value.lastIndexOf(")"))
    .split(/[\s,/]+/)
    .filter(Boolean)
    .map(Number)
  return [parts[0] / 255, parts[1] / 255, parts[2] / 255, parts[3] ?? 1]
}
