import { Plugin } from "@bellucode/plugin/gui"
import en from "./i18n/en"

// Bellu security panels in the session side region. English only for now; other locales fall back to it.
export default Plugin.define({ i18n: { en } })
