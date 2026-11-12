export * as BelluCodeWorkerd from "./workerd"

import { Layer } from "effect"
import type { Config, Scope } from "effect"
import { WorkerdProfile } from "../internal/workerd"
import { BelluCode } from "./bellucode"

export type Configuration = WorkerdProfile.Configuration

export interface CreateOptions<R = never> extends WorkerdProfile.Options {
  readonly log?: BelluCode.CreateOptions["log"]
  readonly plugins?: BelluCode.CreateOptions["plugins"]
  readonly workspaceProviders?: BelluCode.CreateOptions["workspaceProviders"]
  readonly instances?: BelluCode.CreateOptions<R>["instances"]
}

export const create = <R = never>({ log, plugins, workspaceProviders, instances, ...options }: CreateOptions<R>) => {
  const profile = WorkerdProfile.make(options)
  return BelluCode.create(
    { ...profile.options, log, plugins, workspaceProviders, instances },
    { overrides: profile.replacements },
  )
}

export const layer = <R = never>(
  options: CreateOptions<R>,
): Layer.Layer<BelluCode.Service, Config.ConfigError | Error, Exclude<R, Scope.Scope>> =>
  Layer.effect(BelluCode.Service, create(options))

export type Interface = BelluCode.Interface
export type Requirements = Scope.Scope
