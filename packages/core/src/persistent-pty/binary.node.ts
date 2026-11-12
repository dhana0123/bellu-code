export const available = true

export async function resolveBinary() {
  return process.env.BELLUCODE_PTY_BIN || "bellucode-pty"
}
