import { Hono } from "hono"

const page = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex" />
    <title>Session sharing has been discontinued | bellucode</title>
    <style>
      :root {
        --text: hsl(224, 10%, 10%);
        --text-secondary: hsl(224, 7%, 46%);
        --border: hsl(224, 6%, 77%);
        --background: #ffffff;
        --logo-a: #211e1e;
        --logo-b: #656363;
        --logo-c: #cfcecd;
        --padding: 3rem;
        --vertical-padding: 1.5rem;
        --heading: 1.375rem;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          --text: hsl(0, 0%, 100%);
          --text-secondary: hsl(224, 6%, 66%);
          --border: hsl(224, 6%, 36%);
          --background: #0c0c0e;
          --logo-a: #f1ecec;
          --logo-b: #b7b1b1;
          --logo-c: #4b4646;
        }
      }
      @media (max-width: 30rem) {
        :root {
          --padding: 1rem;
          --vertical-padding: 0.75rem;
          --heading: 1rem;
        }
      }
      * {
        box-sizing: border-box;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: calc(var(--padding) + 1rem);
        background: var(--background);
        color: var(--text);
        font-family: "Berkeley Mono", "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,
          "Liberation Mono", "Courier New", monospace;
        -webkit-font-smoothing: antialiased;
      }
      main {
        max-width: 40rem;
        width: 100%;
        border: 1px solid var(--border);
      }
      header {
        padding: var(--padding);
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: var(--vertical-padding);
        text-align: center;
      }
      svg {
        width: clamp(200px, 85vw, 400px);
        height: auto;
      }
      .a {
        fill: var(--logo-a);
      }
      .b {
        fill: var(--logo-b);
      }
      .c {
        fill: var(--logo-c);
      }
      h1 {
        margin: 0;
        font-size: var(--heading);
        font-weight: 500;
        line-height: 1.25;
        text-transform: uppercase;
      }
      p {
        margin: 0;
        max-width: 28rem;
        line-height: 1.6;
        color: var(--text-secondary);
      }
      nav {
        display: flex;
        border-top: 1px solid var(--border);
      }
      nav a {
        flex: 1;
        padding: var(--vertical-padding) 1rem;
        text-align: center;
        text-transform: uppercase;
        line-height: 1.4;
        color: var(--text);
        text-decoration: underline;
        text-underline-offset: 0.1875rem;
        text-decoration-thickness: 1px;
      }
      nav a + a {
        border-left: 1px solid var(--border);
      }
      @media (max-width: 40rem) {
        nav {
          flex-direction: column;
        }
        nav a + a {
          border-left: none;
          border-top: 1px solid var(--border);
        }
      }
    </style>
  </head>
  <body>
    <main>
      <header>
        <a href="https://opencode.ai" aria-label="bellucode">
          <svg viewBox="0 0 234 42" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M-0 35.89V6.11H14.07C18.91 6.11 21.33 8.52 21.33 13.36V15.95C21.33 16.93 21.04 17.76 20.46 18.45L18.95 20.27L20.76 21.78C21.71 22.55 22.19 23.71 22.19 25.23V28.64C22.19 33.48 19.77 35.89 14.94 35.89H-0ZM6.22 30.28H14.68C15.54 30.28 15.97 29.85 15.97 28.99V24.67C15.97 23.81 15.54 23.37 14.68 23.37H6.22V30.28ZM6.22 17.76H13.81C14.68 17.76 15.11 17.33 15.11 16.47V13.01C15.11 12.15 14.68 11.72 13.81 11.72H6.22V17.76Z" fill="currentColor" />
          <path d="M26.43 35.89V6.11H46.81V11.72H32.65V17.76H45.51V23.37H32.65V30.28H46.81V35.89H26.43Z" fill="currentColor" />
          <path d="M50.76 35.89V6.11H56.98V30.28H69.84V35.89H50.76Z" fill="currentColor" />
          <path d="M72.68 35.89V6.11H78.9V30.28H91.76V35.89H72.68Z" fill="currentColor" />
          <path d="M94.35 28.64V6.11H100.56V28.99C100.56 29.85 101 30.28 101.86 30.28H110.32C111.18 30.28 111.62 29.85 111.62 28.99V6.11H117.83V28.64C117.83 33.48 115.41 35.89 110.58 35.89H101.6C96.77 35.89 94.35 33.48 94.35 28.64Z" fill="currentColor" />
          <path d="M131.15 28.64V13.36C131.15 8.52 133.57 6.11 138.4 6.11H149.93L152.82 8.35V11.72H138.66C137.8 11.72 137.37 12.15 137.37 13.01V28.99C137.37 29.85 137.8 30.28 138.66 30.28H152.82V33.65L149.93 35.89H138.4C133.57 35.89 131.15 33.48 131.15 28.64Z" fill="currentColor" />
          <path d="M156.36 28.64V13.36C156.36 8.52 158.78 6.11 163.61 6.11H173.46C178.29 6.11 180.71 8.52 180.71 13.36V28.64C180.71 33.48 178.29 35.89 173.46 35.89H163.61C158.78 35.89 156.36 33.48 156.36 28.64ZM162.58 28.99C162.58 29.85 163.01 30.28 163.87 30.28H173.2C174.06 30.28 174.49 29.85 174.49 28.99V13.01C174.49 12.15 174.06 11.72 173.2 11.72H163.87C163.01 11.72 162.58 12.15 162.58 13.01V28.99Z" fill="currentColor" />
          <path d="M185.63 35.89V6.11H196.94C205.06 6.11 209.11 10.16 209.11 18.28V23.72C209.11 31.84 205.06 35.89 196.94 35.89H185.63ZM191.85 30.28H197.29C201.03 30.28 202.9 28.41 202.9 24.67V17.33C202.9 13.59 201.03 11.72 197.29 11.72H191.85V30.28Z" fill="currentColor" />
          <path d="M213.62 35.89V6.11H234V11.72H219.84V17.76H232.7V23.37H219.84V30.28H234V35.89H213.62Z" fill="currentColor" />
        </svg>
        </a>
        <h1>Session sharing has been discontinued</h1>
        <p>bellucode no longer hosts shared sessions. This link and its content are no longer available.</p>
      </header>
      <nav>
        <a href="https://opencode.ai">Home</a>
        <a href="https://opencode.ai/docs">Docs</a>
        <a href="https://github.com/anomalyco/opencode">GitHub</a>
        <a href="https://opencode.ai/discord">Discord</a>
      </nav>
    </main>
  </body>
</html>`

// V1 clients still create, sync, and remove shares on this host, and the V1 GitHub Action fails its run when share
// creation fails. Accept those requests without storing anything so existing clients keep working.
export default new Hono()
  .post("/api/share", async (c) => {
    const body = await c.req.json<{ sessionID: string }>()
    const id = body.sessionID.slice(-8)
    return c.json({ id, secret: "discontinued", url: new URL(`/share/${id}`, c.req.url).toString() })
  })
  .post("/api/share/:shareID/sync", (c) => c.json({}))
  .delete("/api/share/:shareID", (c) => c.json({}))
  .all("*", (c) => c.html(page, 410))
