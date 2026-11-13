import { cyrb53 } from "./generated"

// Default project marks: a solid shape with the project's first letter inside. Each color has its own shape, so a
// color and its shape always go together; the color is picked from the project key unless the user chose one.
export const PROJECT_AVATAR_COLOR_SHAPES = {
  orange: "hexagon",
  yellow: "octagon",
  cyan: "circle",
  green: "square",
  red: "diamond",
  pink: "pentagon",
  blue: "shield",
  purple: "leaf",
  gray: "pill",
} as const

export type ProjectAvatarShapeColor = keyof typeof PROJECT_AVATAR_COLOR_SHAPES
export type ProjectAvatarShape = (typeof PROJECT_AVATAR_COLOR_SHAPES)[ProjectAvatarShapeColor]

// Gray is the "no color chosen" default, so it is left out of the automatic rotation.
export const PROJECT_AVATAR_SHAPE_COLORS = ["orange", "yellow", "cyan", "green", "red", "pink", "blue", "purple"] as const

/** The color picked from the project key, used when the user has not chosen one. */
export function projectAvatarColor(key: string): ProjectAvatarShapeColor {
  return PROJECT_AVATAR_SHAPE_COLORS[cyrb53(`${key}|color`) % PROJECT_AVATAR_SHAPE_COLORS.length]
}

/** SVG path data for each shape on a 16×16 grid, sized so a letter fits inside. */
export const PROJECT_AVATAR_SHAPE_PATHS: Record<ProjectAvatarShape, string> = {
  hexagon: "M8 0.5 14.5 4.25V11.75L8 15.5 1.5 11.75V4.25Z",
  octagon: "M5 0.5H11L15.5 5V11L11 15.5H5L0.5 11V5Z",
  circle: "M8 0.5a7.5 7.5 0 1 1 0 15a7.5 7.5 0 1 1 0-15Z",
  square: "M0.5 0.5H15.5V15.5H0.5Z",
  diamond: "M8 0 16 8 8 16 0 8Z",
  pentagon: "M8 0.5 15.5 6 12.6 15.5H3.4L0.5 6Z",
  shield: "M8 0.5 15 2.5V8C15 11.8 12 14.4 8 15.5 4 14.4 1 11.8 1 8V2.5Z",
  leaf: "M15.5 0.5V8A7.5 7.5 0 0 1 8 15.5H0.5V8A7.5 7.5 0 0 1 8 0.5Z",
  pill: "M5 2H11a6 6 0 0 1 0 12H5a6 6 0 0 1 0-12Z",
}
