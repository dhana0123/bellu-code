type Provider = {
  id: string
  integrationID?: string
  name: string
}

export function consoleProviderGroup<T extends Provider>(providers: readonly T[]) {
  const root = providers.find((provider) => provider.id === "bellucode" && provider.integrationID === "bellucode")
  const suffix = " / Bellu Code"

  if (!root?.name.endsWith(suffix)) return
  const workspace = root.name.slice(0, -suffix.length).trim()

  if (!workspace) return
  const prefix = `${workspace} / `

  return {
    root,
    workspace,
    prefix,
    providers: providers.filter(
      (provider) => provider.integrationID === "bellucode" && provider.name.startsWith(prefix),
    ),
  }
}

// A signed-in Console workspace adds its own providers next to the free `bellucode` catalog.
export function consoleCatalogLoaded(providers: readonly Provider[]) {
  return (
    consoleProviderGroup(providers) !== undefined ||
    providers.some((provider) => provider.integrationID === "bellucode" && provider.id !== "bellucode")
  )
}

export function consoleProviderName(group: { prefix: string }, name: string) {
  return name.startsWith(group.prefix) ? name.slice(group.prefix.length) : name
}
