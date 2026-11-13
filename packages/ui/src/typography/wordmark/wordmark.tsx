import { createUniqueId, type ComponentProps } from "solid-js"

export function Wordmark(
  props: Pick<ComponentProps<"svg">, "class"> & { fade?: boolean; muted?: boolean; outline?: boolean },
) {
  const mask = createUniqueId()
  const maskGradient = createUniqueId()

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 720 129"
      fill="none"
      classList={{
        [props.class ?? ""]: !!props.class,
        "overflow-visible [&_path]:[vector-effect:non-scaling-stroke]": props.outline,
      }}
    >
      <g opacity={props.muted === false ? 1 : 0.6} class="[[data-color-scheme=dark]_&]:opacity-100">
        <g mask={props.fade === false ? undefined : `url(#${mask})`}>
          <g
            opacity={props.muted === false ? 1 : 0.16 * 0.7}
            fill={props.outline ? "none" : "currentColor"}
            stroke={props.outline ? "currentColor" : undefined}
            stroke-width={props.outline ? 1 : undefined}
          >
            <path
              pathLength={props.outline ? 1 : undefined}
              d="M0 109.83V18.17H43.3C58.18 18.17 65.62 25.61 65.62 40.49V48.46C65.62 51.47 64.73 54.04 62.96 56.16L58.31 61.74L63.89 66.39C66.81 68.78 68.27 72.32 68.27 77.02V87.51C68.27 102.39 60.83 109.83 45.96 109.83H0ZM19.13 92.56H45.16C47.82 92.56 49.15 91.23 49.15 88.57V75.29C49.15 72.63 47.82 71.31 45.16 71.31H19.13V92.56ZM19.13 54.04H42.5C45.16 54.04 46.49 52.71 46.49 50.05V39.43C46.49 36.77 45.16 35.44 42.5 35.44H19.13V54.04Z"
            />
            <path
              pathLength={props.outline ? 1 : undefined}
              d="M81.34 109.83V18.17H144.03V35.44H100.46V54.04H140.05V71.31H100.46V92.56H144.03V109.83H81.34Z"
            />
            <path
              pathLength={props.outline ? 1 : undefined}
              d="M156.19 109.83V18.17H175.31V92.56H214.9V109.83H156.19Z"
            />
            <path
              pathLength={props.outline ? 1 : undefined}
              d="M223.64 109.83V18.17H242.77V92.56H282.35V109.83H223.64Z"
            />
            <path
              pathLength={props.outline ? 1 : undefined}
              d="M290.3 87.51V18.17H309.43V88.57C309.43 91.23 310.76 92.56 313.41 92.56H339.45C342.1 92.56 343.43 91.23 343.43 88.57V18.17H362.56V87.51C362.56 102.39 355.12 109.83 340.24 109.83H312.62C297.74 109.83 290.3 102.39 290.3 87.51Z"
            />
            <path
              pathLength={props.outline ? 1 : undefined}
              d="M403.54 87.51V40.49C403.54 25.61 410.98 18.17 425.85 18.17H461.32L470.22 25.08V35.44H426.65C423.99 35.44 422.67 36.77 422.67 39.43V88.57C422.67 91.23 423.99 92.56 426.65 92.56H470.22V102.92L461.32 109.83H425.85C410.98 109.83 403.54 102.39 403.54 87.51Z"
            />
            <path
              pathLength={props.outline ? 1 : undefined}
              d="M481.11 87.51V40.49C481.11 25.61 488.55 18.17 503.43 18.17H533.71C548.59 18.17 556.03 25.61 556.03 40.49V87.51C556.03 102.39 548.59 109.83 533.71 109.83H503.43C488.55 109.83 481.11 102.39 481.11 87.51ZM500.24 88.57C500.24 91.23 501.57 92.56 504.22 92.56H532.92C535.57 92.56 536.9 91.23 536.9 88.57V39.43C536.9 36.77 535.57 35.44 532.92 35.44H504.22C501.57 35.44 500.24 36.77 500.24 39.43V88.57Z"
            />
            <path
              pathLength={props.outline ? 1 : undefined}
              d="M571.17 109.83V18.17H605.97C630.94 18.17 643.43 30.66 643.43 55.63V72.37C643.43 97.34 630.94 109.83 605.97 109.83H571.17ZM590.3 92.56H607.03C618.55 92.56 624.3 86.8 624.3 75.29V52.71C624.3 41.2 618.55 35.44 607.03 35.44H590.3V92.56Z"
            />
            <path
              pathLength={props.outline ? 1 : undefined}
              d="M657.31 109.83V18.17H720V35.44H676.43V54.04H716.02V71.31H676.43V92.56H720V109.83H657.31Z"
            />
          </g>
        </g>
      </g>
      <defs>
        <mask id={mask} style="mask-type:alpha" maskUnits="userSpaceOnUse" x="0" y="0" width="720" height="129">
          <rect width="720" height="129" fill={`url(#${maskGradient})`} />
        </mask>
        <linearGradient id={maskGradient} x1="360" y1="68" x2="360" y2="129" gradientUnits="userSpaceOnUse">
          <stop stop-color="white" stop-opacity="0.7" />
          <stop offset="1" stop-color="white" stop-opacity="0" />
        </linearGradient>
      </defs>
    </svg>
  )
}
