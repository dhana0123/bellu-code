import { chromium } from "@playwright/test"
import { readFileSync } from "node:fs"
const password = JSON.parse(readFileSync(process.env.HOME + "/.config/bellucode/service-local.json", "utf8")).password
const browser = await chromium.launch({ executablePath: "/snap/bin/chromium", args: ["--no-sandbox"] })
const ctx = await browser.newContext({ httpCredentials: { username: "bellucode", password }, viewport: { width: 1400, height: 900 } })
const page = await ctx.newPage()
await page.goto("http://127.0.0.1:4096/")
await page.getByText("Use password").first().click()
await page.locator('input[type="password"]').first().fill(password)
await page.getByRole("button", { name: /connect/i }).click()
await page.waitForTimeout(3000); await page.screenshot({path:"/tmp/menu-dbg.png"}); console.log(page.url(), (await page.locator("body").innerText()).slice(0,400).replace(/\n/g," | "))
await page.getByText("Greeting").first().click({ timeout: 15000 })
await page.waitForTimeout(1500)
const box = async (sel: string) => page.locator(sel).first().boundingBox()
const r = (b: any) => (b ? `x=${Math.round(b.x)} y=${Math.round(b.y)} w=${Math.round(b.width)} h=${Math.round(b.height)}` : "absent")
const report = async (label: string, trig: string, pop: string) => {
  const t = await box(trig), p = await box(pop)
  console.log(label, "| trigger", r(t), "| popup", r(p), "| nearOrigin", p ? p.x < 20 && p.y < 20 : "n/a")
}
const run = async (tag: string) => {
  console.log("==", tag)
  const attach = page.locator('[data-action="composer-attach"]').first()
  if (await attach.count()) {
    await attach.click(); await page.waitForTimeout(400)
    await report("add menu", '[data-action="composer-attach"]', '[role="menu"]')
    await page.screenshot({ path: `/tmp/menu-${tag}-add.png` })
    const sub = page.locator('[data-action="composer-security"]').first()
    if (await sub.count()) {
      await sub.hover(); await page.waitForTimeout(500)
      const menus = page.locator('[role="menu"]')
      console.log("menus", await menus.count())
      const p = await menus.last().boundingBox()
      console.log("security sub", "| trigger", r(await sub.boundingBox()), "| popup", r(p), "| nearOrigin", p ? p.x < 20 && p.y < 20 : "n/a")
      await page.screenshot({ path: `/tmp/menu-${tag}-sub.png` })
    }
    await page.keyboard.press("Escape"); await page.keyboard.press("Escape")
  } else console.log("attach absent")
  const side = page.locator('[data-action="vertical-tabs-security"]').first()
  if (await side.count() && await side.isVisible()) {
    await side.hover(); await page.waitForTimeout(600)
    await report("sidebar flyout", '[data-action="vertical-tabs-security"]', '[aria-label="Security"][role]')
    await page.screenshot({ path: `/tmp/menu-${tag}-side.png` })
    await page.mouse.move(700, 400)
  } else console.log("sidebar security absent")
  const tb = page.locator('[data-action="titlebar-security"]').first()
  if (await tb.count() && await tb.isVisible()) {
    await tb.hover(); await page.waitForTimeout(600)
    await report("titlebar flyout", '[data-action="titlebar-security"]', '[aria-label="Security"][role]')
    await page.screenshot({ path: `/tmp/menu-${tag}-title.png` })
  } else console.log("titlebar security absent")
}
await run("session")
await page.setViewportSize({ width: 390, height: 800 }); await page.waitForTimeout(800)
await run("mobile")
await page.setViewportSize({ width: 1400, height: 900 })
await browser.close()
