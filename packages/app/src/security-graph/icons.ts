import type { Brand, Language, NodeKind } from "./model"

// One family of icons: 24px grid, monoline, rounded caps and joins, drawn in currentColor.
const open = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">`

/** Outline of a gear with 8 rounded teeth, centered on (12, 12). */
const gear = (() => {
  const teeth = 8
  const step = (Math.PI * 2) / teeth
  const inner = 8.4
  const outer = 10.5
  const point = (radius: number, angle: number) =>
    `${(12 + radius * Math.cos(angle)).toFixed(2)} ${(12 + radius * Math.sin(angle)).toFixed(2)}`
  return Array.from({ length: teeth }, (_, index) => {
    const angle = index * step - Math.PI / 2
    return [
      point(inner, angle - step * 0.34),
      point(outer, angle - step * 0.2),
      point(outer, angle + step * 0.2),
      point(inner, angle + step * 0.34),
    ].join("L")
  })
    .map((part, index) => `${index === 0 ? "M" : "L"}${part}`)
    .join("") + "Z"
})()

const BODY = {
  api: `<path d="${gear}"/><circle cx="12" cy="12" r="6.1"/><text x="12" y="14.15" text-anchor="middle" font-size="5.6" font-weight="700" letter-spacing="0.2" fill="currentColor" stroke="none" style="font-family:inherit">API</text>`,
  "data-model": `<rect x="9" y="3" width="6" height="5" rx="1.2"/><rect x="2.5" y="16" width="6" height="5" rx="1.2"/><rect x="9" y="16" width="6" height="5" rx="1.2"/><rect x="15.5" y="16" width="6" height="5" rx="1.2"/><path d="M12 8v8M5.5 16v-4.5h13V16"/>`,
  dependency: `<rect x="3" y="3" width="18" height="4.6" rx="1.6"/><rect x="3" y="9.7" width="18" height="4.6" rx="1.6"/><rect x="3" y="16.4" width="18" height="4.6" rx="1.6"/><path d="M7 5.3h.01M7 12h.01M7 18.7h.01"/>`,
  module: `<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5M12 22V12"/>`,
  framework: `<rect x="3" y="3" width="18" height="18" rx="3.5"/><path d="m8.8 6.2-2.2 1.8 2.2 1.8M15.2 6.2l2.2 1.8-2.2 1.8M13 6l-2 4"/><rect x="10" y="11.8" width="4" height="2.4" rx=".8"/><path d="M12 14.2v1.1M8 17v-1.7h8V17"/><rect x="6" y="17" width="4" height="2.2" rx=".7"/><rect x="14" y="17" width="4" height="2.2" rx=".7"/>`,
  repository: `<circle cx="6" cy="5.5" r="2.2"/><circle cx="6" cy="18.5" r="2.2"/><circle cx="18" cy="9" r="2.2"/><path d="M6 7.7v8.6M18 11.2c0 3.6-6 2.4-11 5.4"/>`,
  "cloud-resource": `<path d="M7 18.5a4.5 4.5 0 0 1-.6-8.96A6 6 0 0 1 18 10.5a4 4 0 0 1-.5 8Z"/>`,
  package: `<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m7.5 4.3 9 5.2M3.3 7 12 12l8.7-5M12 22V12"/>`,
  vulnerability: `<path d="M12 3 2.5 20h19Z"/><path d="M12 10v4.5M12 17.4v.01"/>`,
  account: `<circle cx="12" cy="8.5" r="3.6"/><path d="M4.5 20c.8-3.8 3.8-6 7.5-6s6.7 2.2 7.5 6"/>`,
} as const satisfies Record<Exclude<NodeKind, "internal-dependency" | "service">, string>

/** White line icon of a node kind. The internal dependency shares the dependency icon. */
export function kindIcon(kind: Exclude<NodeKind, "service">) {
  const key = kind === "internal-dependency" ? "dependency" : kind
  return `${open}${BODY[key]}</svg>`
}

// Official marks. Stripe and Auth0 come from simple-icons (CC0); the OpenAI mark is the one the app ships for providers.
// Each mark remains the trademark of its owner.
const BRAND = {
  stripe: {
    box: "0 0 24 24",
    color: "#635BFF",
    path: "M13.976 9.15c-2.172-.806-3.356-1.426-3.356-2.409 0-.831.683-1.305 1.901-1.305 2.227 0 4.515.858 6.09 1.631l.89-5.494C18.252.975 15.697 0 12.165 0 9.667 0 7.589.654 6.104 1.872 4.56 3.147 3.757 4.992 3.757 7.218c0 4.039 2.467 5.76 6.476 7.219 2.585.92 3.445 1.574 3.445 2.583 0 .98-.84 1.545-2.354 1.545-1.875 0-4.965-.921-6.99-2.109l-.9 5.555C5.175 22.99 8.385 24 11.714 24c2.641 0 4.843-.624 6.328-1.813 1.664-1.305 2.525-3.236 2.525-5.732 0-4.128-2.524-5.851-6.594-7.305h.003z",
  },
  auth0: {
    box: "0 0 24 24",
    color: "#EB5424",
    path: "M21.98 7.448L19.62 0H4.347L2.02 7.448c-1.352 4.312.03 9.206 3.815 12.015L12.007 24l6.157-4.552c3.755-2.81 5.182-7.688 3.815-12.015l-6.16 4.58 2.343 7.45-6.157-4.597-6.158 4.58 2.358-7.433-6.188-4.55 7.63-.045L12.008 0l2.356 7.404 7.615.044z",
  },
  openai: {
    box: "4 4 32 32",
    color: "currentColor",
    path: "M32.8377 17.282C33.2127 16.25 33.3072 15.218 33.2127 14.1875C33.1197 13.1571 32.7447 12.1251 32.2752 11.1876C31.4322 9.78209 30.2127 8.6571 28.8072 8.0001C27.3072 7.34461 25.7127 7.15711 24.1197 7.53211C23.3698 6.78212 22.5253 6.12512 21.5878 5.65713C20.6503 5.18913 19.5253 5.00013 18.4948 5.00013C16.8851 4.99074 15.3125 5.48246 13.9948 6.40712C12.6824 7.34311 11.7449 8.6571 11.2754 10.1571C10.1504 10.4376 9.21289 10.9071 8.27539 11.4696C7.4324 12.1251 6.77541 12.9696 6.21291 13.8126C5.36992 15.2195 5.08792 16.8125 5.27542 18.407C5.46399 19.9968 6.11605 21.496 7.1504 22.718C6.79608 23.7086 6.66795 24.7659 6.77541 25.8124C6.86991 26.8444 7.2449 27.8749 7.7129 28.8124C8.55739 30.2194 9.77538 31.3444 11.1824 31.9999C12.6824 32.6569 14.2753 32.8444 15.8698 32.4694C16.6198 33.2194 17.4628 33.8749 18.4003 34.3444C19.3378 34.8139 20.4628 34.9999 21.4948 34.9999C23.1043 35.0097 24.6769 34.5185 25.9947 33.5944C27.3072 32.6569 28.2447 31.3444 28.7127 29.8444C29.7719 29.6432 30.7682 29.1934 31.6197 28.5319C32.4627 27.8749 33.2127 27.1249 33.6822 26.1874C34.5251 24.7819 34.8071 23.1875 34.6196 21.5945C34.4322 20 33.8697 18.5015 32.8377 17.282ZM21.5878 33.0304C20.0878 33.0304 18.9628 32.5609 17.9323 31.7179C17.9323 31.7179 18.0253 31.6234 18.1198 31.6234L24.1197 28.1554C24.2862 28.0803 24.4196 27.9469 24.4947 27.7804C24.5698 27.636 24.6021 27.4731 24.5877 27.3109V18.875L27.1197 20.375V27.3124C27.1455 28.0547 27.0215 28.7945 26.755 29.4878C26.4885 30.181 26.085 30.8134 25.5687 31.3473C25.0523 31.8811 24.4337 32.3054 23.7497 32.5949C23.0658 32.8843 22.3305 33.0314 21.5878 33.0304ZM9.49488 27.8749C8.83789 26.7499 8.55739 25.4374 8.83789 24.125C8.83789 24.125 8.93239 24.2195 9.02539 24.2195L15.0253 27.6874C15.1693 27.7638 15.3325 27.7966 15.4948 27.7819C15.6823 27.7819 15.8698 27.7819 15.9628 27.6874L23.2753 23.4695V26.3749L17.1823 29.9374C16.5506 30.3042 15.8527 30.5427 15.1287 30.6393C14.4046 30.7358 13.6686 30.6884 12.9629 30.4999C11.4629 30.1249 10.2449 29.1874 9.49488 27.8749ZM7.9004 14.8445C8.56239 13.7234 9.58826 12.8627 10.8074 12.4056V19.532C10.8074 19.718 10.8074 19.907 10.9004 20C10.9755 20.1665 11.1089 20.2998 11.2754 20.375L18.5878 24.5944L16.0573 26.0944L10.0574 22.625C9.41842 22.2639 8.85742 21.7797 8.40684 21.2004C7.95627 20.6211 7.62506 19.9582 7.4324 19.25C7.05741 17.8445 7.1504 16.157 7.9004 14.8445ZM28.6197 19.625L21.3073 15.407L23.8377 13.9071L29.8377 17.375C30.7752 17.9375 31.5252 18.6875 31.9947 19.625C32.4642 20.5625 32.7447 21.5945 32.6502 22.7195C32.5603 23.7755 32.1699 24.7837 31.5252 25.6249C30.8697 26.4694 30.0252 27.1249 28.9947 27.4999V20.375C28.9947 20.1875 28.9947 20 28.9002 19.907C28.9002 19.907 28.8072 19.718 28.6197 19.625ZM31.1502 15.875C31.1502 15.875 31.0572 15.782 30.9627 15.782L24.9627 12.3126C24.7752 12.2196 24.6822 12.2196 24.4947 12.2196C24.3072 12.2196 24.1197 12.2196 24.0252 12.3126L16.7128 16.532V13.6251L22.8073 10.0626C23.7448 9.50009 24.7752 9.31259 25.9002 9.31259C26.9322 9.31259 27.9627 9.68759 28.9002 10.3446C29.7447 11.0001 30.4947 11.8446 30.8697 12.7821C31.2447 13.7196 31.3377 14.8445 31.1502 15.875ZM15.4003 21.125L12.8699 19.625V12.5946C12.8699 11.5626 13.1503 10.4376 13.7128 9.59459C14.2753 8.6571 15.1198 8.0001 16.0573 7.53211C17.0127 7.05249 18.0956 6.88812 19.1503 7.06261C20.1823 7.15711 21.2128 7.62511 22.0573 8.2821C22.0573 8.2821 21.9628 8.3751 21.8698 8.3751L15.8698 11.8446C15.7033 11.9197 15.57 12.0531 15.4948 12.2196C15.4003 12.4071 15.4003 12.5001 15.4003 12.6876V21.125ZM16.7128 18.125L19.9948 16.25L23.2753 18.125V21.875L19.9948 23.75L16.7128 21.875V18.125Z",
  },
} as const satisfies Record<Brand, { box: string; color: string; path: string }>

/** Full-color logo of a third-party service. */
export function brandLogo(brand: Brand) {
  const mark = BRAND[brand]
  return `<svg viewBox="${mark.box}" aria-hidden="true" focusable="false"><path d="${mark.path}" fill="${mark.color}"/></svg>`
}

/** Small round language mark: a dark navy outline, no fill. */
export function languageMark(language: Language) {
  const ring = `<circle cx="8" cy="8" r="7.1"/>`
  const body =
    language === "csharp"
      ? `<text x="8" y="10.4" text-anchor="middle" font-size="6.6" font-weight="700" fill="currentColor" stroke="none" style="font-family:inherit">C#</text>`
      : `<path d="M5.1 7.6h4.8v1.9a2.3 2.3 0 0 1-2.3 2.3h-.2a2.3 2.3 0 0 1-2.3-2.3Z"/><path d="M9.9 8.2h.5a1.05 1.05 0 0 1 0 2.1h-.5M6.5 4.4c.6.7-.6 1.1 0 1.8M8.5 4c.6.7-.6 1.1 0 1.8"/>`
  return `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${ring}${body}</svg>`
}
