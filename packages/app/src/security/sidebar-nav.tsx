import { HoverCard } from "@kobalte/core/hover-card"
import { For, Show } from "solid-js"
import { createStore } from "solid-js/store"
import { Icon } from "@bellucode/ui/icon"
import { IconButton } from "@bellucode/ui/icon-button"
import { useLanguage } from "@/runtime/i18n/language"
import { useSecurityNav } from "./nav-context"
import type { SECURITY_PAGES } from "./nav-items"

const ITEM_CLASS =
  "group flex h-7 w-full shrink-0 items-center gap-2 rounded-md px-2 text-start text-[13px] leading-4 text-v2-text-text-faint hover:text-v2-text-text-base data-[state=pressed]:text-v2-text-text-base focus-visible:outline-none focus-visible:[box-shadow:inset_0_0_0_0.5px_var(--v2-border-border-muted)]"

type SecurityItems = ReturnType<typeof useSecurityNav>

// Every page and placeholder, as rows. `inset` indents them under the accordion's header.
function SecurityRows(props: { security: SecurityItems; inset?: boolean }) {
  const language = useLanguage()
  const row = () => (props.inset ? `${ITEM_CLASS} ps-6` : ITEM_CLASS)

  const page = (item: (typeof SECURITY_PAGES)[number]) => (
    <button
      type="button"
      data-titlebar-tab-action
      data-action={`security-${item.page}`}
      data-state={props.security.active() === item.page ? "pressed" : undefined}
      aria-current={props.security.active() === item.page ? "page" : undefined}
      class={row()}
      onClick={() => props.security.open(item.page)}
    >
      <Icon name={item.icon} class="shrink-0" />
      <span class="min-w-0 truncate">{language.t(item.label)}</span>
    </button>
  )

  return (
    <>
      <For each={props.security.items()}>{page}</For>
      <For each={props.security.soon}>
        {(item) => (
          <button
            type="button"
            data-titlebar-tab-action
            class={row()}
            onClick={() => props.security.announce(item.label)}
          >
            <Icon name={item.icon} class="shrink-0" />
            <span class="min-w-0 truncate">{language.t(item.label)}</span>
          </button>
        )}
      </For>
    </>
  )
}

const FLYOUT_CLASS =
  "z-50 flex min-w-48 flex-col gap-0.5 rounded-xl bg-v2-background-bg-base p-1.5 shadow-[var(--v2-elevation-floating)] outline-none"

/**
 * Security in the vertical sidebar. Hovering the header opens a flyout beside the sidebar with every page; clicking
 * expands the same list in place. The flyout gives way once the list is expanded.
 */
export function SecuritySidebarNav() {
  const language = useLanguage()
  const security = useSecurityNav()
  const [state, setState] = createStore({ open: false, hover: false })
  // The page being viewed keeps its group open.
  const expanded = () => state.open || security.active() !== undefined

  return (
    <nav class="flex w-full shrink-0 flex-col gap-[3px]" aria-label={language.t("home.security")}>
      <HoverCard
        placement="right-start"
        gutter={8}
        openDelay={100}
        closeDelay={150}
        open={state.hover && !expanded()}
        onOpenChange={(open) => setState("hover", open)}
      >
        <HoverCard.Trigger as="div" class="w-full">
          <button
            type="button"
            data-titlebar-tab-action
            data-action="vertical-tabs-security"
            class={ITEM_CLASS}
            aria-expanded={expanded()}
            onClick={() => setState("open", !expanded())}
          >
            <Icon name="security-dashboard" class="shrink-0" />
            <span class="min-w-0 flex-1 truncate">{language.t("home.security")}</span>
            <Icon
              name="chevron-down"
              size="small"
              class="shrink-0 text-v2-icon-icon-muted transition-transform duration-[120ms]"
              style={{ transform: expanded() ? undefined : "rotate(-90deg)" }}
            />
          </button>
        </HoverCard.Trigger>
        <HoverCard.Portal>
          <HoverCard.Content dir={language.direction()} aria-label={language.t("home.security")} class={FLYOUT_CLASS}>
            <SecurityRows security={security} />
          </HoverCard.Content>
        </HoverCard.Portal>
      </HoverCard>
      <Show when={expanded()}>
        <SecurityRows security={security} inset />
      </Show>
    </nav>
  )
}

/** Security in the horizontal titlebar: an icon whose hover flyout lists the security pages. */
export function SecurityFlyout() {
  const language = useLanguage()
  const security = useSecurityNav()

  return (
    <HoverCard placement="bottom-start" gutter={6} openDelay={100} closeDelay={150}>
      <HoverCard.Trigger as="span" class="shrink-0">
        <IconButton
          type="button"
          variant="ghost-muted"
          size="large"
          class="!w-9 shrink-0"
          data-action="titlebar-security"
          state={security.active() ? "pressed" : undefined}
          icon={<Icon name="security-dashboard" />}
          aria-label={language.t("home.security")}
          onClick={() => security.open(security.active() ?? security.items()[0].page)}
        />
      </HoverCard.Trigger>
      <HoverCard.Portal>
        <HoverCard.Content dir={language.direction()} aria-label={language.t("home.security")} class={FLYOUT_CLASS}>
          <SecurityRows security={security} />
        </HoverCard.Content>
      </HoverCard.Portal>
    </HoverCard>
  )
}
