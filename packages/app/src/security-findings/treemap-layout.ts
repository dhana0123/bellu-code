export type Rect = { x: number; y: number; w: number; h: number }

/** Squarified treemap (Bruls, Huizing and van Wijk). Values must be sorted in descending order. */
export function squarify(values: readonly number[], width: number, height: number): Rect[] {
  const total = values.reduce((sum, value) => sum + value, 0)
  if (total === 0) return []
  const areas = values.map((value) => (value / total) * width * height)
  const rects: Rect[] = []
  const bounds = { x: 0, y: 0, w: width, h: height }
  let start = 0
  while (start < areas.length) {
    const side = Math.min(bounds.w, bounds.h)
    let end = start + 1
    while (end < areas.length && worst(areas.slice(start, end + 1), side) <= worst(areas.slice(start, end), side)) end++
    const row = areas.slice(start, end)
    const sum = row.reduce((acc, area) => acc + area, 0)
    if (bounds.w >= bounds.h) {
      // The row fills a column on the left edge.
      const columnWidth = sum / bounds.h
      row.reduce((y, area) => {
        rects.push({ x: bounds.x, y, w: columnWidth, h: area / columnWidth })
        return y + area / columnWidth
      }, bounds.y)
      bounds.x += columnWidth
      bounds.w -= columnWidth
    } else {
      const rowHeight = sum / bounds.w
      row.reduce((x, area) => {
        rects.push({ x, y: bounds.y, w: area / rowHeight, h: rowHeight })
        return x + area / rowHeight
      }, bounds.x)
      bounds.y += rowHeight
      bounds.h -= rowHeight
    }
    start = end
  }
  return rects
}

function worst(row: readonly number[], side: number) {
  const sum = row.reduce((acc, area) => acc + area, 0)
  return Math.max((side * side * Math.max(...row)) / (sum * sum), (sum * sum) / (side * side * Math.min(...row)))
}
