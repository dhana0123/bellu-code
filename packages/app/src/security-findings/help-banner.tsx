import { createStore } from "solid-js/store"
import { For, Show } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { Glyph } from "./glyph"

const SLIDES = ["one", "two"] as const

export function HelpBanner(props: { tips: boolean; onTipsChange: (value: boolean) => void; onClose: () => void }) {
  const language = useLanguage()
  const [state, setState] = createStore({ slide: 0 })
  const last = SLIDES.length - 1
  return (
    <section data-slot="help-banner" aria-label={language.t("security.findings.help.title")}>
      <button
        type="button"
        data-slot="icon-button"
        class="sf-banner-close"
        aria-label={language.t("security.findings.help.close")}
        onClick={() => props.onClose()}
      >
        <Glyph name="close" />
      </button>
      <span data-slot="help-mark" aria-hidden="true">
        ?
      </span>
      <div data-slot="help-body">
        <h2>{language.t("security.findings.help.title")}</h2>
        <Show
          when={state.slide === 0}
          fallback={
            <>
              <p>{language.t("security.findings.help.slide2.body")}</p>
              <ul>
                <li>{language.t("security.findings.help.slide2.bullet1")}</li>
                <li>{language.t("security.findings.help.slide2.bullet2")}</li>
              </ul>
            </>
          }
        >
          <p>{language.t("security.findings.help.body")}</p>
          <ul>
            <li>{language.t("security.findings.help.bullet1")}</li>
            <li>{language.t("security.findings.help.bullet2")}</li>
          </ul>
        </Show>
        <div data-slot="help-links">
          <a href="#learn-more" onClick={(event) => event.preventDefault()}>
            <Glyph name="external" />
            {language.t("security.findings.help.learnMore")}
          </a>
          <a href="#watch-video" onClick={(event) => event.preventDefault()}>
            <Glyph name="play" />
            {language.t("security.findings.help.watchVideo")}
          </a>
        </div>
        <div data-slot="help-footer">
          <button
            type="button"
            class="sf-button"
            data-variant="outline"
            disabled={state.slide === 0}
            onClick={() => setState("slide", (value) => Math.max(0, value - 1))}
          >
            {language.t("security.findings.help.back")}
          </button>
          <button
            type="button"
            class="sf-button"
            data-variant="primary"
            disabled={state.slide === last}
            onClick={() => setState("slide", (value) => Math.min(last, value + 1))}
          >
            {language.t("security.findings.help.next")}
          </button>
          <span data-slot="dots" aria-hidden="true">
            <For each={SLIDES}>{(_, index) => <span data-active={index() === state.slide ? "" : undefined} />}</For>
          </span>
          <span data-slot="slide-label" aria-live="polite">
            {language.t("security.findings.help.slide", { current: state.slide + 1, total: SLIDES.length })}
          </span>
          <label data-slot="tips">
            <input
              type="checkbox"
              checked={props.tips}
              onChange={(event) => props.onTipsChange(event.currentTarget.checked)}
            />
            {language.t("security.findings.help.tips")}
          </label>
        </div>
      </div>
      <button type="button" data-slot="video" aria-label={language.t("security.findings.help.watchVideo")}>
        <span data-slot="play">
          <Glyph name="play" size={18} />
        </span>
      </button>
    </section>
  )
}
