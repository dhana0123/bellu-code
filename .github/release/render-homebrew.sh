#!/usr/bin/env bash
# render-homebrew.sh <sign-macos dir> <build-archives dir> <tap dir>: writes Formula bellucode-v2.rb with the
# hashes of the signed macOS and the Linux archives.
. "$(dirname "$0")/lib.sh"

macos=$1 archives=$2 tap=$3
sum() { sha256 "$1" | cut -c1-64; }
base="https://opencode.ai/files/bin/$OPENCODE_VERSION"
cat > "$tap/bellucode-v2.rb" <<FORMULA
# typed: false
# frozen_string_literal: true

class BellucodeV2 < Formula
  desc "BelluCode V2 - the AI coding agent for the terminal"
  homepage "https://github.com/anomalyco/opencode"
  version "$BELLUCODE_VERSION"
  license "MIT"

  depends_on "ripgrep"
  conflicts_with "bellucode", because: "both install an bellucode binary"

  on_macos do
    if Hardware::CPU.arm?
      url "$base/bellucode-darwin-arm64.zip"
      sha256 "$(sum "$macos/bellucode-darwin-arm64.zip")"
    else
      url "$base/bellucode-darwin-x64-baseline.zip"
      sha256 "$(sum "$macos/bellucode-darwin-x64-baseline.zip")"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$base/bellucode-linux-arm64.tar.gz"
      sha256 "$(sum "$archives/bellucode-linux-arm64.tar.gz")"
    else
      url "$base/bellucode-linux-x64-baseline.tar.gz"
      sha256 "$(sum "$archives/bellucode-linux-x64-baseline.tar.gz")"
    end
  end

  def install
    bin.install "bellucode"
  end
end
FORMULA
cat "$tap/bellucode-v2.rb"
