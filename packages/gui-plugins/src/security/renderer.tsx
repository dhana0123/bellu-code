import { Icon } from "@bellucode/ui/icon"
import { MenuItem, Panel, type IconName, type PanelTab, type Plugin } from "@bellucode/plugin/gui"
import type Security from "./index"

// One tab each. Their content is not built yet, so each shows what it will hold.
const TABS = [
  { id: "findings", icon: "security-findings", order: 40 },
  { id: "graph", icon: "security-graph", order: 41 },
] as const satisfies readonly { id: string; icon: IconName; order: number }[]

type TabID = (typeof TABS)[number]["id"]

const setup: Plugin.Setup<typeof Security> = (ctx) => {
  const layout = ctx.layout
  const sessions = ctx.sessions
  const title = (id: TabID) => ctx.t(`${id}.title`)
  // Tab objects live as long as the plugin, so strip updates and session switches never rebuild a trigger.
  const tabs = Object.fromEntries(
    TABS.map((item): [TabID, PanelTab] => [
      item.id,
      {
        id: item.id,
        get title() {
          return title(item.id)
        },
      },
    ]),
  ) as Record<TabID, PanelTab>
  const known = (id: string): id is TabID => Object.hasOwn(tabs, id)

  for (const item of TABS) {
    ctx.add(MenuItem, (): MenuItem | undefined => {
      const session = sessions.current()
      if (!session?.project || layout.narrow()) return undefined
      const key = `${ctx.id}:${item.id}`
      return {
        menu: "session.panel",
        id: item.id,
        title: title(item.id),
        icon: item.icon,
        order: item.order,
        opened: layout.state(key, session) !== "closed",
        run: () => layout.open(key, session, { tab: "select" }),
      }
    })
  }

  ctx.add(Panel, {
    id: "main",
    region: "side",
    list: (input) => (layout.narrow() ? [] : input.open.filter(known).map((id) => tabs[id])),
    render: (props) => {
      const item = () => TABS.find((tab) => tab.id === props.tab.id) ?? TABS[0]
      return (
        <div class="flex h-full min-h-0 flex-col items-center justify-center gap-3 px-8 text-center">
          <Icon name={item().icon} size="large" class="text-v2-icon-icon-muted" />
          <div class="text-13-medium text-v2-text-text-base">{title(item().id)}</div>
          <p class="m-0 max-w-[320px] text-13-regular text-v2-text-text-muted">{ctx.t(`${item().id}.description`)}</p>
          <span class="rounded-sm bg-v2-background-bg-layer-02 px-2 py-0.5 text-11-regular text-v2-text-text-muted">
            {ctx.t("soon")}
          </span>
        </div>
      )
    },
  })
}

export default setup
