import type { LocalProject } from "@/shell/state/layout"
import {
  displayName,
  getProjectAvatarGenerated,
  getProjectAvatarSource,
  getProjectAvatarVariant,
  ProjectAvatar,
} from "@bellucode/ui/project-avatar"

// The project avatar never changes while a session works: callers show `ActivityRing` at the row's trailing edge, as
// session tabs do.
// The home lists show larger marks than the 16px tab default.
const LARGE = { width: "24px", height: "24px", "--project-avatar-letter-size": "13px" }

export function SessionTabAvatarView(props: {
  project?: LocalProject
  directory: string
  unread: boolean
  large?: boolean
}) {
  return (
    <ProjectAvatar
      fallback={displayName(props.project ?? { worktree: props.directory })}
      src={getProjectAvatarSource(props.project?.id, props.project?.icon)}
      variant={getProjectAvatarVariant(props.project?.icon?.color)}
      generated={getProjectAvatarGenerated(props.project ?? { worktree: props.directory })}
      unread={props.unread}
      style={props.large ? LARGE : undefined}
    />
  )
}
