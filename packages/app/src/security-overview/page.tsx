import { Loader } from "@bellucode/ui/loader"
import { For, Match, Switch } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { CategoryCard } from "./category-card"
import { createOverviewData } from "./data"
import "./overview.css"
/** The Security Overview: one card per Category, in the order the API returns them. */
export function SecurityOverviewPage() {
  const language = useLanguage()
  const data = createOverviewData()
  return (
    <div data-component="security-overview" class="mx-auto w-full max-w-[1200px] px-6 py-4">
      <h1 data-slot="overview-heading">{language.t("home.security.overview")}</h1>
      <Switch>
        <Match when={data.state.status === "error"}>
          <div data-slot="overview-error" role="alert">
            <div>
              <strong>{language.t("home.security.overview.error.title")}</strong>
              <p>{language.t("home.security.overview.error.description")}</p>
            </div>
            <button type="button" data-slot="overview-retry" onClick={() => void data.retry()}>
              {language.t("home.security.overview.retry")}
            </button>
          </div>
        </Match>
        <Match when={data.state.status === "loading"}>
          <div data-slot="overview-loading" role="status">
            <Loader class="size-4" />
            <span>{language.t("security.loading")}</span>
          </div>
        </Match>
        <Match when={data.state.status === "ready"}>
          <ul data-slot="overview-grid">
            <For each={data.state.categories}>{(category) => <CategoryCard category={category} />}</For>
          </ul>
        </Match>
      </Switch>
    </div>
  )
}
