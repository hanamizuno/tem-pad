#!/usr/bin/env bash
# LaunchAgent の plist をプレースホルダ置換して ~/Library/LaunchAgents に配置する。
#
#   deploy/launchd/install.sh            # 配置のみ
#   deploy/launchd/install.sh --load     # 配置して launchctl に登録
#
# 置換される値:
#   __TEM_PAD_BIN__  tem-pad の実行ファイル (uv tool install 後の ~/.local/bin/tem-pad など)
#   __ALLOY_BIN__    alloy の実行ファイル
#   __HOME__         $HOME
#   __REPO__         このリポジトリの絶対パス
#   __HOST__         general.host に合わせるホスト名 (hostname -s)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
dest="$HOME/Library/LaunchAgents"
mkdir -p "$dest" "$HOME/Library/Logs/tem-pad"

tem_pad_bin="${TEM_PAD_BIN:-$(command -v tem-pad || true)}"
alloy_bin="${ALLOY_BIN:-$(command -v alloy || true)}"
host="${TEM_PAD_HOST:-$(hostname -s)}"

if [ -z "$tem_pad_bin" ]; then
  echo "tem-pad が PATH にありません。TEM_PAD_BIN=/path/to/tem-pad を指定してください" >&2
  exit 1
fi

render() {
  sed -e "s|__TEM_PAD_BIN__|$tem_pad_bin|g" \
      -e "s|__ALLOY_BIN__|$alloy_bin|g" \
      -e "s|__HOME__|$HOME|g" \
      -e "s|__REPO__|$repo|g" \
      -e "s|__HOST__|$host|g" \
      "$1" > "$2"
  echo "wrote $2"
}

render "$here/com.tem-pad.collect.plist" "$dest/com.tem-pad.collect.plist"
if [ -n "$alloy_bin" ]; then
  render "$here/com.tem-pad.alloy.plist" "$dest/com.tem-pad.alloy.plist"
else
  echo "alloy が PATH にないため com.tem-pad.alloy.plist は配置しませんでした (brew services を使う場合は不要)" >&2
fi

if [ "${1:-}" = "--load" ]; then
  uid="$(id -u)"
  for label in com.tem-pad.collect com.tem-pad.alloy; do
    plist="$dest/$label.plist"
    [ -f "$plist" ] || continue
    launchctl bootout "gui/$uid/$label" 2>/dev/null || true
    launchctl bootstrap "gui/$uid" "$plist"
    echo "loaded $label"
  done
fi
