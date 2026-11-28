import { MemoryRouter, useLocation } from "@solidjs/router"
import { SecurityOverviewPage } from "./page"
export default {
  title: "App/Security/Overview",
  id: "app-security-overview",
  args: { scenario: "populated" },
}
// The fixture response comes from the story server's fake SDK: populated, empty, mixed, error, or flaky (fails once).
function Frame() {
  const location = useLocation()
  return (
    <>
      <SecurityOverviewPage />
      <output data-testid="location">{location.pathname + location.search}</output>
    </>
  )
}
export const Playground = {
  render: () => (
    <MemoryRouter>
      <Frame />
    </MemoryRouter>
  ),
}
