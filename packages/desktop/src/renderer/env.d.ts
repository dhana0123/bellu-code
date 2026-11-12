import type { ElectronNative } from "../preload/types"

declare global {
  interface ImportMetaEnv {
    readonly BELLUCODE_TEST_ONBOARDING: boolean
  }

  interface Window {
    electron: ElectronNative
    __BELLUCODE__?: {
      deepLinks?: string[]
    }
  }
}
