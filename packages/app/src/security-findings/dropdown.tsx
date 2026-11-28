import { createEffect, createSignal, For, onCleanup, Show, type JSX } from "solid-js"
import { Portal } from "solid-js/web"

export type DropdownItem = {
  id: string
  label: string
  onSelect: () => void
  /** Present for a toggle item. The menu stays open after it is chosen. */
  checked?: boolean
}

/**
 * A button that opens a menu. The menu is portaled and positioned from the trigger, so a scrolling table or a
 * clipped card never cuts it off. Arrow keys move between items, Esc closes and returns focus to the trigger.
 */
export function Dropdown(props: {
  label: string
  trigger: JSX.Element
  items: DropdownItem[]
  triggerClass?: string
  align?: "start" | "end"
  onTriggerClick?: (event: MouseEvent) => void
}) {
  const [open, setOpen] = createSignal(false)
  const [position, setPosition] = createSignal({ top: 0, left: 0 })
  let trigger!: HTMLButtonElement
  let menu: HTMLDivElement | undefined

  const close = (restore: boolean) => {
    setOpen(false)
    if (restore) trigger.focus()
  }

  const toggle = (event: MouseEvent) => {
    props.onTriggerClick?.(event)
    if (open()) return close(false)
    const rect = trigger.getBoundingClientRect()
    const width = 200
    const left =
      props.align === "end" ? Math.max(8, rect.right - width) : Math.min(rect.left, window.innerWidth - width - 8)
    setPosition({ top: rect.bottom + 4, left })
    setOpen(true)
  }

  createEffect(() => {
    if (!open()) return
    const focusable = () => [...(menu?.querySelectorAll<HTMLElement>("[role^=menuitem]") ?? [])]
    queueMicrotask(() => focusable()[0]?.focus({ preventScroll: true }))
    const outside = (event: PointerEvent) => {
      const target = event.target as Node
      if (!menu?.contains(target) && !trigger.contains(target)) close(false)
    }
    const dismiss = () => close(false)
    document.addEventListener("pointerdown", outside, true)
    window.addEventListener("resize", dismiss)
    window.addEventListener("scroll", dismiss, true)
    onCleanup(() => {
      document.removeEventListener("pointerdown", outside, true)
      window.removeEventListener("resize", dismiss)
      window.removeEventListener("scroll", dismiss, true)
    })
  })

  const onKeyDown = (event: KeyboardEvent) => {
    const items = [...(menu?.querySelectorAll<HTMLElement>("[role^=menuitem]") ?? [])]
    const index = items.indexOf(document.activeElement as HTMLElement)
    if (event.key === "Escape") {
      event.preventDefault()
      event.stopPropagation()
      return close(true)
    }
    if (event.key === "Tab") return close(false)
    const next =
      event.key === "ArrowDown"
        ? (index + 1) % items.length
        : event.key === "ArrowUp"
          ? (index - 1 + items.length) % items.length
          : event.key === "Home"
            ? 0
            : event.key === "End"
              ? items.length - 1
              : undefined
    if (next === undefined) return
    event.preventDefault()
    items[next]?.focus()
  }

  return (
    <>
      <button
        ref={trigger}
        type="button"
        class={props.triggerClass}
        aria-label={props.label}
        aria-haspopup="menu"
        aria-expanded={open()}
        onClick={toggle}
      >
        {props.trigger}
      </button>
      <Show when={open()}>
        <Portal>
          <div
            ref={menu}
            data-component="security-findings-menu"
            role="menu"
            aria-label={props.label}
            style={{ top: `${position().top}px`, left: `${position().left}px` }}
            onKeyDown={onKeyDown}
            // Solid bubbles portaled events to the owner, so a menu click must not reach the table row.
            onClick={(event) => event.stopPropagation()}
          >
            <For each={props.items}>
              {(item) => (
                <button
                  type="button"
                  role={item.checked === undefined ? "menuitem" : "menuitemcheckbox"}
                  aria-checked={item.checked}
                  tabindex="-1"
                  onClick={() => {
                    item.onSelect()
                    if (item.checked === undefined) close(true)
                  }}
                >
                  <span data-slot="menu-check" aria-hidden="true">
                    {item.checked ? "✓" : ""}
                  </span>
                  {item.label}
                </button>
              )}
            </For>
          </div>
        </Portal>
      </Show>
    </>
  )
}
