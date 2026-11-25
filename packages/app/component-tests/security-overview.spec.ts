import { expect, story } from "../../stories/playwright/story"

const CARDS = [
  ["cloud_infrastructure", "Cloud infrastructure", "Resources and networks"],
  ["identity", "Identity", "Users and permissions"],
  ["vulnerabilities", "Vulnerabilities", "CVEs and packages"],
  ["network_exposure", "Network exposure", "Connectivity and reachability"],
  ["secrets", "Secrets", "Credentials and access"],
  ["data_security", "Data security", "Databases and sensitive data"],
  ["code_and_dependencies", "Code and dependencies", "Repositories and IaC"],
  ["runtime", "Runtime", "Activity and threats"],
  ["ai_security", "AI security", "Models and agents"],
] as const
const SEVERITY_LABELS = ["Critical", "High", "Medium", "Low", "Info"]
const ID = "app-security-overview--playground"

story("shows nine cards in order with titles, subtitles, names and graph links", async ({ mount, page }) => {
  const root = await mount(ID, { args: { scenario: "populated" } })
  const cards = root.locator('[data-slot="overview-card"]')
  await expect(cards).toHaveCount(9)
  await expect(cards.locator('[data-slot="card-title"]')).toHaveText(CARDS.map((card) => card[1]))
  await expect(cards.locator('[data-slot="card-subtitle"]')).toHaveText(CARDS.map((card) => card[2]))
  await Promise.all(
    CARDS.map(async ([id, title], index) => {
      const link = cards.nth(index).locator('[data-slot="card-link"]')
      await expect(cards.nth(index)).toHaveAttribute("data-category", id)
      await expect(link).toHaveAttribute(
        "href",
        `/security/graph?lens=${encodeURIComponent(`category-${id.replaceAll("_", "-")}`)}`,
      )
      await expect(link).toHaveAccessibleName(`${title}, ${1200 + index} entities`)
    }),
  )
  await expect(cards.locator('[data-slot="card-empty"]')).toHaveCount(0)
  await expect(page.locator('[data-slot="overview-error"]')).toHaveCount(0)
})

story("shows all five severity labels per card, with zeros, and at most three top issues", async ({ mount }) => {
  const root = await mount(ID, { args: { scenario: "populated" } })
  const cards = root.locator('[data-slot="overview-card"]')
  await expect(cards).toHaveCount(9)
  for (const index of [0, 1, 2, 3, 4, 5, 6, 7, 8]) {
    const severity = cards.nth(index).locator('[data-slot="card-severity"] > li')
    await expect(severity.locator("span")).toHaveText(SEVERITY_LABELS)
    // The fixture leaves medium and low at zero on every card, and info at 7.
    await expect(severity.locator("strong")).toHaveText([String(index % 3), String(index + 1), "0", "0", "7"])
    await expect(cards.nth(index).locator('[data-slot="card-issues"] > li')).toHaveCount(index % 4)
  }
})

story("an empty category links to connector setup and shows zero counts", async ({ mount }) => {
  const root = await mount(ID, { args: { scenario: "empty" } })
  const cards = root.locator('[data-slot="overview-card"]')
  await expect(cards).toHaveCount(9)
  await expect(cards.locator('[data-slot="card-empty"]')).toHaveCount(9)
  for (const href of await cards.locator('[data-slot="card-connect"]').evaluateAll((links) => links.map((a) => a.getAttribute("href"))))
    expect(href).toBe("/security/connectors")
  await expect(cards.nth(0).locator('[data-slot="card-empty"] p')).toHaveText(/connector/)
  await expect(cards.nth(2).locator('[data-slot="card-empty"] p')).toHaveText(/scanner/)
  await expect(cards.nth(0).locator('[data-slot="card-link"]')).toHaveAccessibleName("Cloud infrastructure, 0 entities")
  await expect(cards.locator('[data-slot="card-count"] strong')).toHaveText(Array(9).fill("0"))
  await expect(cards.locator('[data-slot="card-severity"] strong')).toHaveText(Array(45).fill("0"))
})

story("mixed data empties only the categories without a source", async ({ mount }) => {
  const root = await mount(ID, { args: { scenario: "mixed" } })
  const cards = root.locator('[data-slot="overview-card"]')
  await expect(cards).toHaveCount(9)
  for (const index of [2, 5, 8]) await expect(cards.nth(index).locator('[data-slot="card-empty"]')).toHaveCount(1)
  for (const index of [0, 1, 3, 4, 6, 7]) await expect(cards.nth(index).locator('[data-slot="card-empty"]')).toHaveCount(0)
})

story("Tab moves across the cards in card order and puts the connect link after its card", async ({ mount, page }) => {
  const root = await mount(ID, { args: { scenario: "mixed" } })
  await expect(root.locator('[data-slot="overview-card"]')).toHaveCount(9)
  const order: string[] = []
  // Cards 3, 6 and 9 are empty, so each of them adds a connect link right after its card link.
  for (let step = 0; step < 12; step++) {
    await page.keyboard.press("Tab")
    order.push(
      await page.evaluate(() => {
        const active = document.activeElement
        const card = active?.closest("[data-category]")?.getAttribute("data-category")
        return `${card}:${active?.getAttribute("data-slot")}`
      }),
    )
  }
  expect(order).toEqual(
    CARDS.flatMap(([id], index) => [
      `${id}:card-link`,
      ...(index % 3 === 2 ? [`${id}:card-connect`] : []),
    ]),
  )
})

story("Enter and Space on a focused card open its graph lens", async ({ mount, page }) => {
  const root = await mount(ID, { args: { scenario: "populated" } })
  const location = page.getByTestId("location")
  const links = root.locator('[data-slot="card-link"]')
  await expect(links).toHaveCount(9)
  await links.nth(1).focus()
  await page.keyboard.press("Enter")
  await expect(location).toHaveText("/security/graph?lens=category-identity")
  await links.nth(3).focus()
  await page.keyboard.press("Space")
  await expect(location).toHaveText("/security/graph?lens=category-network-exposure")
})

story("the empty-state link opens connector setup, not the graph", async ({ mount, page }) => {
  const root = await mount(ID, { args: { scenario: "empty" } })
  await root.locator('[data-slot="card-connect"]').first().click()
  await expect(page.getByTestId("location")).toHaveText("/security/connectors")
})

story("a failed fetch shows the error with Retry and no counts, and Retry recovers", async ({ mount, page }) => {
  const root = await mount(ID, { args: { scenario: "flaky" } })
  const error = root.locator('[data-slot="overview-error"]')
  await expect(error).toBeVisible()
  await expect(error).toContainText("The security summaries could not be loaded")
  await expect(root.locator('[data-slot="overview-card"]')).toHaveCount(0)
  await expect(root.locator('[data-slot="card-count"]')).toHaveCount(0)
  await root.getByRole("button", { name: "Retry" }).click()
  await expect(root.locator('[data-slot="overview-card"]')).toHaveCount(9)
  await expect(error).toHaveCount(0)
  await expect(page.locator('[data-slot="overview-card"] [data-slot="card-count"] strong').first()).toHaveText("1,200")
})

story("a persistent failure keeps the error and shows no counts after Retry", async ({ mount }) => {
  const root = await mount(ID, { args: { scenario: "error" } })
  await expect(root.locator('[data-slot="overview-error"]')).toBeVisible()
  await root.getByRole("button", { name: "Retry" }).click()
  await expect(root.locator('[data-slot="overview-error"]')).toBeVisible()
  await expect(root.locator('[data-slot="overview-card"]')).toHaveCount(0)
})
