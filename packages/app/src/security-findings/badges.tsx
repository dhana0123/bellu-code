import { Show } from "solid-js"
import { useLanguage } from "@/runtime/i18n/language"
import { Glyph } from "./glyph"
import type { Provider, Resource, ResourceType, Severity, Tech } from "./model"

export function severityLabelKey(severity: Severity) {
  return `security.findings.severity.${severity}` as const
}

export function resourceTypeLabelKey(type: ResourceType) {
  return `security.findings.resourceType.${type}` as const
}

/** Severity is always spelled out. The color only reinforces the label. */
export function SeverityPill(props: { severity: Severity }) {
  const language = useLanguage()
  return (
    <span data-slot="pill" data-severity={props.severity}>
      {language.t(severityLabelKey(props.severity))}
    </span>
  )
}

export function StatusPill() {
  const language = useLanguage()
  return (
    <span data-slot="pill" data-status="unresolved">
      {language.t("security.findings.status.unresolved")}
    </span>
  )
}

const LETTERS = { critical: "C", high: "H", medium: "M", low: "L" } as const

/** A small letter chip with a count, for example the red "C 59" next to an orange "H 323". */
export function RiskChip(props: { severity: Severity; count: number }) {
  const language = useLanguage()
  return (
    <span
      data-slot="chip"
      data-severity={props.severity}
      role="img"
      aria-label={language.t("security.findings.chip.label", {
        severity: language.t(severityLabelKey(props.severity)),
        count: props.count,
      })}
    >
      <span aria-hidden="true">{LETTERS[props.severity]}</span>
      <span aria-hidden="true" data-slot="chip-count">
        {props.count.toLocaleString()}
      </span>
    </span>
  )
}

const TECH_LABEL: Record<Tech, string> = {
  java: "Jv",
  python: "Py",
  javascript: "JS",
  go: "Go",
  os: "OS",
  browser: "Fx",
}

export function TechBadge(props: { tech: Tech }) {
  return (
    <span data-slot="tech" data-tech={props.tech} aria-hidden="true">
      {TECH_LABEL[props.tech]}
    </span>
  )
}

export function ResourceGlyph(props: { type: ResourceType }) {
  return <Glyph name={props.type === "container-image" ? "container" : props.type} class="sf-icon" />
}

const PROVIDER_LABEL: Record<Provider, string> = { aws: "AWS", azure: "Azure", gcp: "GCP", github: "GitHub" }

export function ProviderGlyph(props: { provider: Provider }) {
  return (
    <span data-slot="provider" data-provider={props.provider} title={PROVIDER_LABEL[props.provider]}>
      <Glyph name={props.provider === "github" ? "repository" : "cloud"} class="sf-icon" />
    </span>
  )
}

/**
 * A long name that keeps its start and end, for example an image digest. The full name is the tooltip. Splitting
 * at the last 12 characters keeps the distinguishing tail visible when the middle is cut off.
 */
export function MiddleTruncate(props: { text: string; tail?: number }) {
  const tail = () => props.tail ?? 12
  const split = () => props.text.length > tail() * 2
  return (
    <span data-slot="middle" title={props.text}>
      <span data-slot="middle-start">{split() ? props.text.slice(0, -tail()) : props.text}</span>
      <Show when={split()}>
        <span data-slot="middle-end">{props.text.slice(-tail())}</span>
      </Show>
    </span>
  )
}

export function resourceTypeText(resource: Resource, language: ReturnType<typeof useLanguage>) {
  return language.t(resourceTypeLabelKey(resource.type))
}
