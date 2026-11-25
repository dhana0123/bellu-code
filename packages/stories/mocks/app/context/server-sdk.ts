import { useServer } from "@/runtime/server/current"
import { ServerScope } from "@/runtime/server/scope"
import { overviewFixture } from "./overview-fixtures"

const providers = [
  "bellucode-go",
  "bellucode",
  "anthropic",
  "openai",
  "google",
  "openrouter",
  "vercel",
  "github-copilot",
  "302ai",
  "abacus",
  "abliteration",
  "alibaba",
  "alibaba-cn",
  "alibaba-coding-plan",
]

const client = {
  provider: {
    auth: async () => ({
      data: Object.fromEntries(providers.map((provider) => [provider, [{ type: "api", label: "API key" }]])),
    }),
    oauth: {
      authorize: async (input: { method?: number }) => ({
        data: {
          url: "https://example.com/oauth",
          method: input.method === 1 ? ("code" as const) : ("auto" as const),
          instructions: input.method === 1 ? "Paste the authorization code" : "Confirmation code: ABCD-EFGH",
        },
      }),
      callback: async (input: { method?: number }) => {
        if (input.method === 0) return new Promise<never>(() => {})

        return { data: undefined }
      },
    },
  },
  auth: {
    set: async () => ({ data: true }),
  },
  global: {
    dispose: async () => ({ data: true }),
  },
}

// `?args=scenario:<name>` chooses the Overview response: `error` always fails, `flaky` fails once, then answers.
const scenario = new URLSearchParams(location.search).get("args")?.match(/(?:^|;)scenario:([^;]*)/)?.[1] ?? "populated"
let overviewCalls = 0
const api = {
  experimental: {
    overview: {
      categories: async () => {
        overviewCalls++
        if (scenario === "error" || (scenario === "flaky" && overviewCalls === 1)) throw new Error("overview unavailable")
        return overviewFixture(scenario)
      },
    },
  },
  session: {
    form: {
      reply: async () => ({ data: true }),
      cancel: async () => ({ data: true }),
    },
  },
}

const noopStream = {
  on: () => () => undefined,
  listen: () => () => undefined,
}

export function useServerSDK() {
  const server = useServer()

  if ("sdk" in server.ctx) return server.ctx.sdk

  return {
    server: { type: "http" as const, http: { url: "http://storybook.local" } },
    scope: ServerScope.local,
    url: "http://storybook.local",
    http: { url: "http://storybook.local" },
    api,
    client,
    connection: {
      status: () => "disconnected" as const,
      attempt: () => 0,
      error: () => undefined,
    },
    event: {
      ...noopStream,
      location: () => noopStream,
    },
  }
}
