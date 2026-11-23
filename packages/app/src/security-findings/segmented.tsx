import { For } from "solid-js"

export type SegmentedOption<T extends string> = { value: T; label: string; dot?: string }

/**
 * A single-select control built on native radio inputs, so arrow keys, focus and screen reader semantics come from
 * the browser. `dot` names a severity whose color marks the option.
 */
export function Segmented<T extends string>(props: {
  name: string
  label: string
  value: T
  options: SegmentedOption<T>[]
  onChange: (value: T) => void
}) {
  return (
    <div data-slot="segmented" role="radiogroup" aria-label={props.label}>
      <For each={props.options}>
        {(option) => (
          <label data-slot="segment" data-checked={props.value === option.value ? "" : undefined}>
            <input
              type="radio"
              class="sr-only"
              name={props.name}
              value={option.value}
              checked={props.value === option.value}
              onChange={() => props.onChange(option.value)}
            />
            {option.dot ? <span data-slot="dot" data-severity={option.dot} aria-hidden="true" /> : null}
            {option.label}
          </label>
        )}
      </For>
    </div>
  )
}
