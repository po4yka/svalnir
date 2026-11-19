#!/usr/bin/env bash
# Build the macOS release artifacts into dist/ and check them.
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
# scripts/package-layout.sh has the layout of the two artifacts, and
# packaging/README.md describes it. The last step runs
# scripts/check-artifacts.sh on dist/.
#
# Environment:
#   SVALNIR_BIN_DIR         A directory with the four release executables of an
#                           earlier build. The script then runs no build, so
#                           a job with a signing identity runs no build script.
#   SOURCE_DATE_EPOCH       The time of each archive entry, in seconds. The
#                           default is the committer time of HEAD.
#   SVALNIR_SIGNING         "adhoc" (default) or "developer-id".
#   SVALNIR_SIGN_IDENTITY   With "developer-id": the name or the SHA-1 hash of
#                           a "Developer ID Application" identity in a keychain
#                           of the search list.
#   SVALNIR_NOTARIZE        "1" sends the signed artifacts to the Apple notary
#                           service and staples the ticket to Svalnir.app. It
#                           needs "developer-id" signing.
#   SVALNIR_NOTARY_PROFILE  With SVALNIR_NOTARIZE=1: the keychain profile that
#                           `xcrun notarytool store-credentials` made.
#
# By default the artifacts are not signed with a Developer ID and are not
# notarized: each executable and the app bundle have an ad-hoc signature with
# the hardened runtime. The script runs on macOS and needs jq and cargo-about.

set -euo pipefail

cd "$(dirname "$0")/.."

# shellcheck source=scripts/package-layout.sh
source scripts/package-layout.sh

readonly DIST="dist"
readonly ENTITLEMENTS_DIR="packaging/macos/entitlements"
readonly SIGNING="${SVALNIR_SIGNING:-adhoc}"
readonly NOTARIZE="${SVALNIR_NOTARIZE:-0}"

fail() {
    echo "error: $*" >&2
    exit 1
}

# Stop before the build when the signing configuration is not complete.
check_signing_configuration() {
    case "$SIGNING" in
    adhoc)
        [ -z "${SVALNIR_SIGN_IDENTITY:-}" ] ||
            fail "SVALNIR_SIGN_IDENTITY is set, but SVALNIR_SIGNING is not 'developer-id'"
        ;;
    developer-id)
        [ -n "${SVALNIR_SIGN_IDENTITY:-}" ] ||
            fail "SVALNIR_SIGNING=developer-id needs SVALNIR_SIGN_IDENTITY; no signing identity is configured"
        local identities
        identities="$(security find-identity -v -p codesigning)"
        grep -F -- "$SVALNIR_SIGN_IDENTITY" <<<"$identities" | grep -F 'Developer ID Application' >/dev/null ||
            fail "no valid 'Developer ID Application' identity '$SVALNIR_SIGN_IDENTITY' is in the keychain search list"
        ;;
    *)
        fail "SVALNIR_SIGNING is '$SIGNING'; use 'adhoc' or 'developer-id'"
        ;;
    esac
    case "$NOTARIZE" in
    0) ;;
    1)
        [ "$SIGNING" = "developer-id" ] ||
            fail "SVALNIR_NOTARIZE=1 needs SVALNIR_SIGNING=developer-id; the notary service refuses an ad-hoc signature"
        [ -n "${SVALNIR_NOTARY_PROFILE:-}" ] ||
            fail "SVALNIR_NOTARIZE=1 needs SVALNIR_NOTARY_PROFILE; no notary credentials are configured"
        ;;
    *)
        fail "SVALNIR_NOTARIZE is '$NOTARIZE'; use '0' or '1'"
        ;;
    esac
}

# Sign one executable or one bundle: sign_code PATH IDENTIFIER EXECUTABLE_NAME.
# Each signature has the hardened runtime and the entitlements file of the
# executable. An ad-hoc signature has no timestamp, so it is the same for the
# same input. A Developer ID signature has a secure timestamp, which the
# notary service requires.
sign_code() {
    local path="$1" identifier="$2" entitlements="$ENTITLEMENTS_DIR/$3.entitlements"
    local identity=(--sign - --timestamp=none)
    if [ "$SIGNING" = "developer-id" ]; then
        identity=(--sign "$SVALNIR_SIGN_IDENTITY" --timestamp)
    fi
    [ -f "$entitlements" ] || fail "no entitlements file '$entitlements'"
    codesign --force "${identity[@]}" \
        --identifier "$identifier" \
        --options runtime \
        --entitlements "$entitlements" \
        "$path"
}

# Send one zip file to the notary service and wait for the result.
# TODO(npochaev): run the developer-id and notarization steps with a real
# identity; no run of them exists, because the project has no Developer ID.
notarize() {
    xcrun notarytool submit "$1" --keychain-profile "$SVALNIR_NOTARY_PROFILE" --wait
}

# Give each staged entry the same mode and time on each host.
normalize() {
    find "$1" -type d -exec chmod 755 {} +
    find "$1" -type f -exec chmod 644 {} +
    find "$1" -type f \( -path '*/bin/*' -o -path '*/Contents/MacOS/*' \) -exec chmod 755 {} +
    find "$1" -exec env TZ=UTC touch -h -t "$STAMP" {} +
}

# Write a zip archive of one staged directory: zip_tree DIRECTORY OUTPUT.
# The entries are in a fixed order, with UTC times and no extra field.
zip_tree() {
    local parent base output
    parent="$(dirname "$1")"
    base="$(basename "$1")"
    output="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
    rm -f "$output"
    (cd "$parent" && find "$base" -print | LC_ALL=C sort | TZ=UTC zip -X -q -@ "$output")
}

[ "$(uname -s)" = "Darwin" ] || fail "packaging needs macOS"
for tool in jq cargo-about; do
    command -v "$tool" >/dev/null 2>&1 || fail "'$tool' is not installed; see CONTRIBUTING.md#ci-and-releases"
done
check_signing_configuration

metadata="$(cargo metadata --no-deps --format-version 1 --locked)"
version="$(jq -r '[.packages[] | select(.name == "svalnir-cli") | .version] | first // empty' <<<"$metadata")"
target_dir="$(jq -r '.target_directory // empty' <<<"$metadata")"
[ -n "$version" ] || fail "cannot read the workspace version"
[ -n "$target_dir" ] || fail "cannot read the Cargo target directory"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "version '$version' is not MAJOR.MINOR.PATCH"

if [ "$#" -gt 0 ] && [ "$1" != "v$version" ]; then
    fail "tag '$1' does not match the workspace version 'v$version'"
fi

epoch="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || true)}"
[[ "$epoch" =~ ^[0-9]+$ ]] || fail "set SOURCE_DATE_EPOCH: the checkout has no commit time"
STAMP="$(date -u -r "$epoch" +%Y%m%d%H%M.%S)"
readonly STAMP

NAME="$(artifact_name "$version")"
readonly NAME
readonly STAGE="$DIST/stage"

rm -rf "$DIST"
mkdir -p "$STAGE"

if [ -n "${SVALNIR_BIN_DIR:-}" ]; then
    echo "==> use the executables of $SVALNIR_BIN_DIR" >&2
    for bin in "${BINS[@]}"; do
        [ -f "$SVALNIR_BIN_DIR/$bin" ] || fail "SVALNIR_BIN_DIR has no executable '$bin'"
    done
    BIN_SRC="$(cd "$SVALNIR_BIN_DIR" && pwd)"
else
    echo "==> build $NAME" >&2
    # Replace the paths of this host in the executables: the home directory,
    # the Cargo home, the toolchain, the checkout, and the target directory.
    # rustc uses the last option that matches, so the widest prefix is first.
    # scripts/check-artifacts.sh fails when a path of the build host stays.
    remap=""
    for pair in \
        "$HOME=/home" \
        "${CARGO_HOME:-$HOME/.cargo}=/cargo" \
        "$(rustc --print sysroot)=/toolchain" \
        "$PWD=/svalnir" \
        "$target_dir=/target"; do
        remap="$remap --remap-path-prefix=$pair"
    done
    MACOSX_DEPLOYMENT_TARGET="$MIN_MACOS" \
        RUSTFLAGS="${RUSTFLAGS:-}$remap" \
        cargo build --release --locked --workspace --bins --target "$TARGET"
    BIN_SRC="$target_dir/$TARGET/release"
fi
readonly BIN_SRC

echo "==> third-party notices" >&2
readonly NOTICES="$STAGE/THIRD_PARTY_LICENSES.txt"
cargo about generate --locked --fail --output-file "$NOTICES" packaging/about.hbs

echo "==> stage and sign ($SIGNING)" >&2
# The binaries archive: each executable is signed as single code.
readonly ARCHIVE_ROOT="$STAGE/$NAME"
mkdir -p "$ARCHIVE_ROOT/bin"
for bin in "${BINS[@]}"; do
    cp "$BIN_SRC/$bin" "$ARCHIVE_ROOT/bin/$bin"
    sign_code "$ARCHIVE_ROOT/bin/$bin" "$(code_identifier "$bin")" "$bin"
done
cp LICENSE README.md "$NOTICES" "$ARCHIVE_ROOT/"

# The app bundle: sign the nested executables first, then the bundle. The
# signature of the bundle seals the nested code, Info.plist, and Resources, so
# no file of the bundle changes after it.
readonly APP="$STAGE/Svalnir.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
for bin in "${BINS[@]}"; do
    cp "$BIN_SRC/$bin" "$APP/Contents/MacOS/$bin"
done
cp LICENSE "$NOTICES" "$APP/Contents/Resources/"
sed -e "s/@VERSION@/$version/g" \
    -e "s/@BUNDLE_ID@/$BUNDLE_ID/g" \
    -e "s/@MIN_MACOS@/$MIN_MACOS/g" \
    -e "s/@EXECUTABLE@/$BUNDLE_EXECUTABLE/g" \
    packaging/macos/Info.plist.in >"$APP/Contents/Info.plist"
printf 'APPL????' >"$APP/Contents/PkgInfo"
plutil -lint "$APP/Contents/Info.plist" >/dev/null
rm -f "$NOTICES"
normalize "$STAGE"
for bin in "${BINS[@]}"; do
    [ "$bin" = "$BUNDLE_EXECUTABLE" ] ||
        sign_code "$APP/Contents/MacOS/$bin" "$(code_identifier "$bin")" "$bin"
done
sign_code "$APP" "$BUNDLE_ID" "$BUNDLE_EXECUTABLE"
codesign --verify --strict --deep "$APP"
normalize "$STAGE"

if [ "$NOTARIZE" = "1" ]; then
    echo "==> notarize" >&2
    # A ticket can be stapled to a bundle, not to a single executable. For the
    # executables of the binaries archive, Gatekeeper gets the ticket online.
    zip_tree "$APP" "$STAGE/notary-app.zip"
    notarize "$STAGE/notary-app.zip"
    xcrun stapler staple "$APP"
    xcrun stapler validate "$APP"
    zip_tree "$ARCHIVE_ROOT/bin" "$STAGE/notary-bin.zip"
    notarize "$STAGE/notary-bin.zip"
    rm -f "$STAGE/notary-app.zip" "$STAGE/notary-bin.zip"
    normalize "$STAGE"
fi

echo "==> archive" >&2
archive_entries "$version" >"$STAGE/archive.list"
COPYFILE_DISABLE=1 tar --no-mac-metadata --no-xattrs --format ustar \
    --uid 0 --gid 0 --numeric-owner \
    -cf - -C "$STAGE" -n -T "$STAGE/archive.list" |
    gzip -n -9 >"$DIST/$NAME.tar.gz"
zip_tree "$APP" "$DIST/$NAME-app.zip"

echo "==> checksums" >&2
rm -rf "$STAGE"
(cd "$DIST" && shasum -a 256 -- "$NAME.tar.gz" "$NAME-app.zip" >SHA256SUMS)

echo "==> check" >&2
SVALNIR_SIGNING="$SIGNING" SVALNIR_NOTARIZE="$NOTARIZE" scripts/check-artifacts.sh "$DIST"

ls -1 "$DIST"
