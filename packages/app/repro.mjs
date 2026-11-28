import { chromium } from "@playwright/test"
const b = await chromium.launch({ executablePath: "/snap/bin/chromium" })
const p = await b.newPage({ viewport: { width: 1400, height: 900 } })
await p.goto("http://localhost:4096/", { waitUntil: "networkidle" })
await p.waitForTimeout(1500)
if (await p.getByText("Use password").count()) {
  await p.getByText("Use password").click()
  await p.locator('input:not([type="password"])').first().fill("http://localhost:4096")
  await p.locator('input[type="password"]').fill(process.env.PW)
  await p.locator('input[type="password"]').press("Enter")
  await p.waitForTimeout(4000)
}
await p.getByText("Greeting").first().click()
await p.waitForTimeout(4000)
await p.evaluate(() => {
  window.__log = []
  const desc = (n) => n.nodeType !== 1 ? n.nodeName : `${n.tagName.toLowerCase()}[${n.getAttribute("data-component") || n.getAttribute("data-slot") || n.className?.toString().slice(0, 40)}] kids=${n.querySelectorAll("*").length}`
  new MutationObserver((ms) => {
    for (const m of ms) for (const n of m.removedNodes) if (n.nodeType === 1 && n.querySelectorAll("*").length > 50) window.__log.push("REMOVED " + desc(n) + " from " + desc(m.target))
  }).observe(document.body, { subtree: true, childList: true })
})
await p.locator('[data-action="composer-attach"]').first().click()
await p.waitForTimeout(1500)
console.log((await p.evaluate(() => window.__log)).slice(0, 10).join("\n"))
await b.close()
