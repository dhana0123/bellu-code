interface ImportMetaEnv {
  readonly BELLUCODE_CHANNEL: string
  readonly BELLUCODE_VERSION?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
