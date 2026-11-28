/**
 * Copies text. `navigator.clipboard` exists only in secure contexts, and the web UI is also served over plain HTTP
 * on LAN origins, so those fall back to a hidden textarea.
 */
export async function copyText(value: string) {
  if (window.isSecureContext && navigator.clipboard) return navigator.clipboard.writeText(value)
  const area = document.createElement("textarea")
  area.value = value
  area.setAttribute("readonly", "")
  area.style.position = "fixed"
  area.style.opacity = "0"
  document.body.appendChild(area)
  area.select()
  document.execCommand("copy")
  area.remove()
}

export function downloadJson(name: string, value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }))
  const link = document.createElement("a")
  link.href = url
  link.download = name
  link.click()
  URL.revokeObjectURL(url)
}
