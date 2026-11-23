import { For } from "solid-js"
import { Icon } from "@bellucode/ui/icon"
import { Menu } from "@bellucode/ui/menu"
import { useLanguage } from "@/runtime/i18n/language"
import { useSecurityNav } from "./nav-context"
import type { SECURITY_PAGES } from "./nav-items"

/** The add menu's Security item. Hovering or opening it lists every security page, with the unbuilt ones as toasts. */
export function SecurityMenuItem() {
  const language = useLanguage()
  const security = useSecurityNav()

  return (
    <Menu.Sub>
      <Menu.SubTrigger data-action="composer-security">
        <span class="flex items-center gap-2">
          <Icon name="security-dashboard" size="small" class="shrink-0 text-v2-icon-icon-muted" />
          {language.t("home.security")}
        </span>
      </Menu.SubTrigger>
      <Menu.Portal>
        <Menu.SubContent style={{ "min-width": "200px" }}>
          <For each={security.items()}>{(item) => <PageItem item={item} open={security.open} />}</For>
          <For each={security.soon}>
            {(item) => (
              <Menu.Item onSelect={() => security.announce(item.label)}>
                <span class="flex items-center gap-2">
                  <Icon name={item.icon} size="small" class="shrink-0 text-v2-icon-icon-muted" />
                  {language.t(item.label)}
                </span>
              </Menu.Item>
            )}
          </For>
        </Menu.SubContent>
      </Menu.Portal>
    </Menu.Sub>
  )
}

function PageItem(props: {
  item: (typeof SECURITY_PAGES)[number]
  open: (page: (typeof SECURITY_PAGES)[number]["page"]) => void
}) {
  const language = useLanguage()

  return (
    <Menu.Item data-action={`security-${props.item.page}`} onSelect={() => props.open(props.item.page)}>
      <span class="flex items-center gap-2">
        <Icon name={props.item.icon} size="small" class="shrink-0 text-v2-icon-icon-muted" />
        {language.t(props.item.label)}
      </span>
    </Menu.Item>
  )
}
