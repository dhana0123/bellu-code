import { describe, expect, test } from "bun:test"
import { PROJECT_AVATAR_COLOR_SHAPES, PROJECT_AVATAR_SHAPE_COLORS, projectAvatarColor } from "./shape"

describe("project avatar shapes", () => {
  test("every color has its own shape", () => {
    const shapes = Object.values(PROJECT_AVATAR_COLOR_SHAPES)
    expect(new Set(shapes).size).toBe(shapes.length)
  })

  test("the picked color is stable per key and covers every rotation color", () => {
    expect(projectAvatarColor("project-a")).toBe(projectAvatarColor("project-a"))
    const colors = new Set(Array.from({ length: 400 }, (_, i) => projectAvatarColor(`project-${i}`)))
    expect(colors.size).toBe(PROJECT_AVATAR_SHAPE_COLORS.length)
  })
})
