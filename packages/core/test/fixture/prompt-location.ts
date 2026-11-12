import type { FileSystem } from "@bellucode/core/filesystem"
import { Bus } from "@bellucode/core/bus"
import { Image } from "@bellucode/core/image"
import { LocationServiceMap } from "@bellucode/core/location-service-map"
import type { LocationServices } from "@bellucode/core/location-services"
import { Plugin } from "@bellucode/core/plugin"
import { PluginHooks } from "@bellucode/core/plugin/hooks"
import { Skill } from "@bellucode/core/skill"
import type { Location } from "@bellucode/schema/location"
import { makeGlobalNode } from "@bellucode/util/effect/app-node"
import { LayerNode } from "@bellucode/util/effect/layer-node"
import { Effect, Layer, LayerMap } from "effect"

// Plain-prompt unit fixtures use virtual directories.
export const promptLocationNode = makeGlobalNode({
  service: LocationServiceMap.Service,
  layer: Layer.effect(
    LocationServiceMap.Service,
    Effect.gen(function* () {
      const bus = yield* Bus.Service
      return yield* LayerMap.make(
        (_ref: Location.Ref) =>
          LayerNode.compile(LayerNode.group([PluginHooks.node, Image.node, Skill.node, Plugin.node]), {
            replacements: [
              Bus.node.replace(Layer.succeed(Bus.Service, bus)),
              Plugin.node.replace(Layer.mock(Plugin.Service, { awaitActivation: Effect.void })),
            ],
          }) as unknown as Layer.Layer<LocationServices, FileSystem.DirectoryNotFoundError>,
      )
    }),
  ),
  deps: [Bus.node],
})
