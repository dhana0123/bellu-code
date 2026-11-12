import { createEffect, For, on, onCleanup } from "solid-js"
import { createStore } from "solid-js/store"
import { prefersReducedMotion } from "@bellucode/ui/motion"

const target = ["B", "E", "L", "L", "U", "C", "O", "D", "E"] as const

const choices = ["B", "E", "L", "U", "C", "O", "D"] as const
// Slot of each target letter in the 234×42 viewBox; a scrambled letter is centred in its slot.
const slots = [
  { x: 0, w: 22.19 },
  { x: 26.43, w: 20.38 },
  { x: 50.76, w: 19.08 },
  { x: 72.68, w: 19.08 },
  { x: 94.35, w: 23.48 },
  { x: 131.15, w: 21.67 },
  { x: 156.36, w: 24.35 },
  { x: 185.63, w: 23.48 },
  { x: 213.62, w: 20.38 },
]
const widths: Record<(typeof choices)[number], number> = {
  B: 22.19,
  E: 20.38,
  L: 19.08,
  U: 23.48,
  C: 21.67,
  O: 24.35,
  D: 23.48,
}

export function AnimatedWordmark(props: { active: boolean }) {
  const [state, setState] = createStore({ letters: [...target] })
  const timers = new Set<ReturnType<typeof setTimeout>>()

  createEffect(
    on(
      () => props.active,
      (active) => {
        timers.forEach(clearTimeout)
        timers.clear()

        if (!active || prefersReducedMotion()) {
          setState("letters", [...target])

          return
        }

        const starts = target.map(() => choices[Math.floor(Math.random() * choices.length)])
        const settles = target.map(() => 6 + Math.floor(Math.random() * 8))
        const last = Math.max(...settles)
        setState("letters", starts)

        Array.from({ length: last }, (_, index) => index + 1).forEach((tick) => {
          const timer = setTimeout(() => {
            setState(
              "letters",
              target.map((letter, index) =>
                tick >= settles[index] ? letter : choices[Math.floor(Math.random() * choices.length)],
              ),
            )
            timers.delete(timer)
          }, tick * 75)

          timers.add(timer)
        })
      },
    ),
  )

  onCleanup(() => timers.forEach(clearTimeout))

  return (
    <svg class="settings-about-wordmark" viewBox="0 0 234 42" aria-hidden="true">
      <defs>
        <symbol id="settings-about-letter-B" viewBox="0 0 22.19 42">
          <path d="M0 35.89V6.11H14.07C18.91 6.11 21.33 8.52 21.33 13.36V15.95C21.33 16.93 21.04 17.76 20.46 18.45L18.95 20.27L20.76 21.78C21.71 22.55 22.19 23.71 22.19 25.23V28.64C22.19 33.48 19.77 35.89 14.94 35.89H0ZM6.22 30.28H14.68C15.54 30.28 15.97 29.85 15.97 28.99V24.67C15.97 23.81 15.54 23.37 14.68 23.37H6.22V30.28ZM6.22 17.76H13.81C14.68 17.76 15.11 17.33 15.11 16.47V13.01C15.11 12.15 14.68 11.72 13.81 11.72H6.22V17.76Z" />
        </symbol>
        <symbol id="settings-about-letter-E" viewBox="0 0 20.38 42">
          <path d="M0 35.89V6.11H20.38V11.72H6.22V17.76H19.08V23.37H6.22V30.28H20.38V35.89H0Z" />
        </symbol>
        <symbol id="settings-about-letter-L" viewBox="0 0 19.08 42">
          <path d="M0 35.89V6.11H6.22V30.28H19.08V35.89H0Z" />
        </symbol>
        <symbol id="settings-about-letter-U" viewBox="0 0 23.48 42">
          <path d="M0 28.64V6.11H6.21V28.99C6.21 29.85 6.65 30.28 7.51 30.28H15.97C16.83 30.28 17.27 29.85 17.27 28.99V6.11H23.48V28.64C23.48 33.48 21.06 35.89 16.23 35.89H7.25C2.42 35.89 0 33.48 0 28.64Z" />
        </symbol>
        <symbol id="settings-about-letter-C" viewBox="0 0 21.67 42">
          <path d="M0 28.64V13.36C0 8.52 2.42 6.11 7.25 6.11H18.78L21.67 8.35V11.72H7.51C6.65 11.72 6.22 12.15 6.22 13.01V28.99C6.22 29.85 6.65 30.28 7.51 30.28H21.67V33.65L18.78 35.89H7.25C2.42 35.89 0 33.48 0 28.64Z" />
        </symbol>
        <symbol id="settings-about-letter-O" viewBox="0 0 24.35 42">
          <path d="M0 28.64V13.36C0 8.52 2.42 6.11 7.25 6.11H17.1C21.93 6.11 24.35 8.52 24.35 13.36V28.64C24.35 33.48 21.93 35.89 17.1 35.89H7.25C2.42 35.89 0 33.48 0 28.64ZM6.22 28.99C6.22 29.85 6.65 30.28 7.51 30.28H16.84C17.7 30.28 18.13 29.85 18.13 28.99V13.01C18.13 12.15 17.7 11.72 16.84 11.72H7.51C6.65 11.72 6.22 12.15 6.22 13.01V28.99Z" />
        </symbol>
        <symbol id="settings-about-letter-D" viewBox="0 0 23.48 42">
          <path d="M0 35.89V6.11H11.31C19.43 6.11 23.48 10.16 23.48 18.28V23.72C23.48 31.84 19.43 35.89 11.31 35.89H0ZM6.22 30.28H11.66C15.4 30.28 17.27 28.41 17.27 24.67V17.33C17.27 13.59 15.4 11.72 11.66 11.72H6.22V30.28Z" />
        </symbol>
      </defs>
      <For each={state.letters}>
        {(letter, index) => (
          <use
            href={`#settings-about-letter-${letter}`}
            x={slots[index()].x + (slots[index()].w - widths[letter]) / 2}
            width={widths[letter]}
            height="42"
          />
        )}
      </For>
    </svg>
  )
}
