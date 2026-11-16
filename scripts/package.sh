#!/usr/bin/env bash
# Build the macOS release artifacts into dist/.
#
# Usage: scripts/package.sh [TAG]
# If TAG is given, it must be "v" followed by the workspace version in
# Cargo.toml, for example v0.1.0.
#
# The workspace version must be MAJOR.MINOR.PATCH. Pre-release versions are
# not supported, because CFBundleVersion accepts integers only.
#
# Output:
#   dist/svalnir-VERSION-aarch64-apple-darwin.tar.gz      CLI, agent, helper, GUI binaries
#   dist/svalnir-VERSION-aarch64-apple-darwin-app.zip     Svalnir.app
#   dist/SHA256SUMS
# Both artifacts contain LICENSE and THIRD_PARTY_LICENSES.txt.
#
# The artifacts are not signed with a Developer ID and are not notarized.
# The app bundle has an ad-hoc signature only. The script runs on macOS and
# needs jq and cargo-about.

set -euo pipefail

cd "$(dirname "$0")/.."

readonly TARGET="aarch64-apple-darwin"
readonly BUNDLE_ID="dev.po4yka.svalnir"
readonly MIN_MACOS="13.0"
readonly BINS=(svalnir svalnir-agent svalnir-privileged svalnir-gui)
readonly DIST="dist"

fail() {
    echo "error: $*" >&2
    exit 1
}

[ "$(uname -s)" = "Darwin" ] || fail "packaging needs macOS"
for tool in jq cargo-about; do
    command -v "$tool" >/dev/null 2>&1 || fail "'$tool' is not installed; see CONTRIBUTING.md#ci-and-releases"
done

metadata="$(cargo metadata --no-deps --format-version 1 --locked)"
version="$(jq -r '[.packages[] | select(.name == "svalnir-cli") | .version] | first // empty' <<<"$metadata")"
target_dir="$(jq -r '.target_directory // empty' <<<"$metadata")"
[ -n "$version" ] || fail "cannot read the workspace version"
[ -n "$target_dir" ] || fail "cannot read the Cargo target directory"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version '$version' is not MAJOR.MINOR.PATCH"

if [ "$#" -gt 0 ] && [ "$1" != "v$version" ]; then
    fail "tag '$1' does not match the workspace version 'v$version'"
fi

readonly NAME="svalnir-$version-$TARGET"
readonly STAGE="$DIST/stage"

rm -rf "$DIST"
mkdir -p "$STAGE"

echo "==> build $NAME" >&2
MACOSX_DEPLOYMENT_TARGET="$MIN_MACOS" \
    cargo build --release --locked --workspace --bins --target "$TARGET"

readonly BIN_SRC="$target_dir/$TARGET/release"

echo "==> third-party notices" >&2
readonly NOTICES="$STAGE/THIRD_PARTY_LICENSES.txt"
cargo about generate --locked --fail --output-file "$NOTICES" packaging/about.hbs

echo "==> archive" >&2
mkdir -p "$STAGE/$NAME/bin"
for bin in "${BINS[@]}"; do
    cp "$BIN_SRC/$bin" "$STAGE/$NAME/bin/$bin"
done
cp LICENSE README.md "$NOTICES" "$STAGE/$NAME/"
COPYFILE_DISABLE=1 tar --no-mac-metadata --uid 0 --gid 0 --numeric-owner \
    -czf "$DIST/$NAME.tar.gz" -C "$STAGE" "$NAME"

echo "==> app bundle" >&2
readonly APP="$STAGE/Svalnir.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_SRC/svalnir-gui" "$APP/Contents/MacOS/svalnir-gui"
cp LICENSE "$NOTICES" "$APP/Contents/Resources/"
sed -e "s/@VERSION@/$version/g" \
    -e "s/@BUNDLE_ID@/$BUNDLE_ID/g" \
    -e "s/@MIN_MACOS@/$MIN_MACOS/g" \
    packaging/macos/Info.plist.in >"$APP/Contents/Info.plist"
printf 'APPL????' >"$APP/Contents/PkgInfo"
plutil -lint "$APP/Contents/Info.plist" >/dev/null
codesign --force --sign - --identifier "$BUNDLE_ID" --timestamp=none "$APP"
codesign --verify --strict "$APP"
ditto -c -k --norsrc --keepParent "$APP" "$DIST/$NAME-app.zip"

echo "==> checksums" >&2
rm -rf "$STAGE"
(cd "$DIST" && shasum -a 256 -- *.tar.gz *.zip >SHA256SUMS)

ls -1 "$DIST"
