import { Button } from "@bellucode/ui/button"
import { Loader } from "@bellucode/ui/loader"
import { onCleanup, Show, type Component } from "solid-js"
import { createStore } from "solid-js/store"
import { formatCountdown } from "./countdown"

const TICK_MS = 1_000
const COPIED_MS = 2_000
/** The prompt warns when this little time is left. */
const SOON_SECONDS = 60

export type DevicePromptLabels = {
  instructions: string
  code: string
  copy: string
  copied: string
  copyFailed: string
  open: string
  /** The localized "MM:SS remaining" text for a formatted time. */
  remaining: (time: string) => string
  expiresSoon: string
  expired: string
  waiting: string
  cancel: string
}

export type DevicePromptProps = {
  userCode: string
  verificationUri: string
  /** Epoch milliseconds. */
  expiresAt: number
  labels: DevicePromptLabels
  onCancel: () => void
  /** Called after the code reached the clipboard. */
  onCopy?: () => void
  /** Shown above the code when the caller already opened the verification page in a new tab. */
  notice?: string
}

/**
 * Generic device-authorization prompt: the user code, a link to the verification page, a copy action, the time left and
 * a cancel action. It holds no provider-specific text; the caller passes every string. Announcements for assistive tech
 * live in the caller's live region, so the per-second countdown here is never announced.
 */
export const DevicePrompt: Component<DevicePromptProps> = (props) => {
  const [view, setView] = createStore<{ now: number; copy: "idle" | "copied" | "failed" }>({
    now: Date.now(),
    copy: "idle",
  })
  const tick = setInterval(() => setView("now", Date.now()), TICK_MS)
  let reset: ReturnType<typeof setTimeout> | undefined
  let codeElement: HTMLElement | undefined
  onCleanup(() => {
    clearInterval(tick)
    clearTimeout(reset)
  })
  // Best effort: put the code on the clipboard so the user only pastes it on GitHub. Silent when the browser refuses.
  const board = typeof navigator === "undefined" ? undefined : navigator.clipboard
  if (board)
    void Promise.try(() => board.writeText(props.userCode)).then(
      () => setView("copy", "copied"),
      () => undefined,
    )

  const remaining = () => Math.max(0, Math.ceil((props.expiresAt - view.now) / 1000))

  const copy = async () => {
    clearTimeout(reset)
    // `navigator.clipboard` does not exist on plain HTTP origins; the code stays selectable for a manual copy.
    const board = typeof navigator === "undefined" ? undefined : navigator.clipboard
    const written = board ? await Promise.try(() => board.writeText(props.userCode)).then(() => true, () => false) : false
    if (written) props.onCopy?.()
    else if (codeElement) window.getSelection()?.selectAllChildren(codeElement)
    setView("copy", written ? "copied" : "failed")
    reset = setTimeout(() => setView("copy", "idle"), COPIED_MS)
  }

  return (
    <div class="flex flex-col gap-3" data-component="device-prompt">
      <Show when={props.notice} fallback={<p class="m-0 text-13-regular text-v2-text-text-base">{props.labels.instructions}</p>}>
        {(notice) => <p class="m-0 text-13-regular text-v2-text-text-base">{notice()}</p>}
      </Show>
      <div class="flex flex-wrap items-center gap-3">
        <span class="text-13-medium text-v2-text-text-muted">{props.labels.code}</span>
        <code
          ref={codeElement}
          role="img"
          aria-label={props.userCode.split("").join(" ")}
          class="select-text font-mono text-18-medium tracking-widest text-v2-text-text-base"
        >
          {props.userCode}
        </code>
        <Button type="button" size="small" variant="neutral" onClick={() => void copy()}>
          {props.labels.copy}
        </Button>
        <Show when={view.copy !== "idle"}>
          <span class="text-11-regular text-v2-text-text-muted">
            {view.copy === "copied" ? props.labels.copied : props.labels.copyFailed}
          </span>
        </Show>
      </div>
      <a
        href={props.verificationUri}
        target="_blank"
        rel="noopener noreferrer"
        class="w-fit text-13-medium text-v2-text-text-base underline focus-visible:outline-2 focus-visible:outline-offset-2"
      >
        {props.labels.open}
      </a>
      <div class="flex items-center gap-2 text-13-regular text-v2-text-text-muted">
        <Loader class="size-4" aria-hidden="true" />
        <span>{props.labels.waiting}</span>
        <span class="font-mono">
          {remaining() > 0 ? props.labels.remaining(formatCountdown(remaining())) : props.labels.expired}
        </span>
      </div>
      <Show when={remaining() > 0 && remaining() <= SOON_SECONDS}>
        <p class="m-0 text-11-regular text-v2-text-text-muted">{props.labels.expiresSoon}</p>
      </Show>
      <div class="flex justify-end">
        <Button type="button" variant="ghost" onClick={props.onCancel}>
          {props.labels.cancel}
        </Button>
      </div>
    </div>
  )
}
