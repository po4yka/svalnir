#!/usr/bin/env bash
# Check the macOS release artifacts that scripts/package.sh makes.
#
# Usage: scripts/check-artifacts.sh [--no-run] [DIST]
# DIST is the directory of the artifacts; the default is dist/. The script
# unpacks each artifact into a temporary directory, which it removes. It
# installs nothing, registers no service, and does not change DIST.
#
# Checks:
#   files      DIST has the two artifacts and SHA256SUMS, and the sums agree
#   layout     each artifact has exactly the entries of scripts/package-layout.sh,
#              so `svalnir-agent` is beside `svalnir`
#   code       each executable is a regular file with mode 755 for the release
#              architecture and deployment target, with a valid signature, its
#              identifier, the hardened runtime, and no entitlement
#   notices    LICENSE and THIRD_PARTY_LICENSES.txt are in each artifact
#   plist      Info.plist agrees with the workspace version and the contract
#   hygiene    no path of a build host, no test-only switch, and no known
#              secret format is in an executable or a property list
#   run        `svalnir --version`, `svalnir license`, `svalnir doctor`, and
#              `svalnir-agent --version` from each artifact, with a temporary
#              HOME and a temporary state directory. --no-run skips this check.
#
# Environment:
#   SVALNIR_SIGNING   "adhoc" (default) or "developer-id": the signature that
#                     each executable must have.
#   SVALNIR_NOTARIZE  "1" also validates the stapled ticket of Svalnir.app.
#
# The script runs on macOS and needs the Xcode command line tools.

set -euo pipefail

umask 022

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
readonly ROOT

# shellcheck source=scripts/package-layout.sh
source "$ROOT/scripts/package-layout.sh"

readonly SIGNING="${SVALNIR_SIGNING:-adhoc}"
readonly NOTARIZE="${SVALNIR_NOTARIZE:-0}"

# Paths that only a build host has. A release executable must not name them.
# The home directory and the checkout of this host are checked as literals.
# A path below a home directory is a host path only with a directory of the
# toolchain after it: the rules of the product name relative paths such as
# `.cargo/registry/cache`, which can stand next to another string in the
# file. The fixture home of the GUI (`FIXTURE_HOME`) is not a host path.
readonly HOST_PATHS='/Users/runner/|/home/runner|/var/folders/|/private/tmp/|/(Users|home)/[^/]+/\.cargo/(registry|git)/|/(Users|home)/[^/]+/\.rustup/toolchains/|/(Users|home)/[^/]+/\.local/share/mise/installs/'
readonly FIXTURE_HOME='/(Users|home)/fixture/'
# The prefix of each environment variable that only a test build reads.
readonly TEST_SWITCH='SVALNIR_TEST_'
# Formats of well-known credentials. This is a search for an accident, not
# proof that no secret is in a file.
readonly SECRET_FORMATS='BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}'

fail() {
    echo "error: $*" >&2
    exit 1
}

step() {
    echo "--> $*" >&2
}

run=1
if [ "${1:-}" = "--no-run" ]; then
    run=0
    shift
fi
[ "$#" -le 1 ] || fail "usage: scripts/check-artifacts.sh [--no-run] [DIST]"
[ "$(uname -s)" = "Darwin" ] || fail "the artifact check needs macOS"
for tool in codesign lipo otool plutil strings shasum unzip zipinfo; do
    command -v "$tool" >/dev/null 2>&1 || fail "'$tool' is not installed; install the Xcode command line tools"
done
[ -d "${1:-$ROOT/dist}" ] || fail "no directory '${1:-$ROOT/dist}'; run scripts/package.sh first"
DIST="$(cd "${1:-$ROOT/dist}" && pwd)"
readonly DIST

version="$(sed -n '/^\[workspace\.package\]$/,/^\[/s/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "cannot read the workspace version from Cargo.toml"
NAME="$(artifact_name "$version")"
readonly NAME
readonly ARCHIVE="$DIST/$NAME.tar.gz"
readonly APP_ZIP="$DIST/$NAME-app.zip"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/svalnir-artifacts.XXXXXX")"
readonly WORK
trap 'rm -rf "$WORK"' EXIT

# Fail when two lists of lines differ: same_lines WHAT EXPECTED ACTUAL.
same_lines() {
    if [ "$2" != "$3" ]; then
        echo "error: $1 differs from the layout contract (< contract, > artifact):" >&2
        diff <(echo "$2") <(echo "$3") >&2 || true
        exit 1
    fi
}

# Print the printable strings of a file. `|| true`: a reader that stops early
# closes the pipe.
file_strings() {
    strings -a "$1" || true
}

# Fail when a file has a string that matches a pattern: no_match FILE WHAT PATTERN.
no_match() {
    local found
    found="$(file_strings "$1" | grep -E -m 3 -- "$3" || true)"
    [ -z "$found" ] || fail "$(basename "$1") has $2: $(head -c 300 <<<"$found")"
}

check_hygiene() {
    local file="$1" found literal
    found="$(file_strings "$file" | grep -E -o -- "$HOST_PATHS" | grep -E -v -- "^$FIXTURE_HOME" | head -n 3 || true)"
    [ -z "$found" ] || fail "$(basename "$file") has a path of a build host: $(head -c 300 <<<"$found")"
    no_match "$file" "a test-only switch" "$TEST_SWITCH"
    no_match "$file" "a known secret format" "$SECRET_FORMATS"
    for literal in "$ROOT" "$HOME"; do
        found="$(file_strings "$file" | grep -F -m 1 -- "$literal" || true)"
        [ -z "$found" ] || fail "$(basename "$file") has the path '$literal' of this host"
    done
}

# Check one executable: check_code FILE NAME.
check_code() {
    local file="$1" bin="$2" mode archs minos description entitlements
    [ -f "$file" ] && [ ! -L "$file" ] || fail "$file is not a regular file"
    mode="$(stat -f %Lp "$file")"
    [ "$mode" = "755" ] || fail "$file has mode $mode, not 755"
    archs="$(lipo -archs "$file")"
    [ "$archs" = "$MACHO_ARCH" ] || fail "$file has the architectures '$archs', not '$MACHO_ARCH'"
    minos="$(otool -l "$file" | awk '$1 == "cmd" { build = ($2 == "LC_BUILD_VERSION") } build && !found && $1 == "minos" { print $2; found = 1 }')"
    [ "$minos" = "$MIN_MACOS" ] || fail "$file has the deployment target '$minos', not '$MIN_MACOS'"

    codesign --verify --strict "$file" || fail "$file has no valid signature"
    description="$(codesign --display --verbose=4 "$file" 2>&1)"
    grep -Fxq "Identifier=$(code_identifier "$bin")" <<<"$description" ||
        fail "$file does not have the identifier '$(code_identifier "$bin")'"
    grep -Eq '^CodeDirectory .*flags=[^ ]*runtime' <<<"$description" ||
        fail "$file does not have the hardened runtime"
    case "$SIGNING" in
    adhoc)
        grep -Fxq "Signature=adhoc" <<<"$description" || fail "$file does not have an ad-hoc signature"
        ;;
    developer-id)
        grep -Eq '^Authority=Developer ID Application: ' <<<"$description" ||
            fail "$file is not signed with a Developer ID Application identity"
        grep -Eq '^Timestamp=' <<<"$description" || fail "$file has no secure timestamp"
        ;;
    *)
        fail "SVALNIR_SIGNING is '$SIGNING'; use 'adhoc' or 'developer-id'"
        ;;
    esac
    entitlements="$(codesign --display --entitlements - --xml "$file" 2>/dev/null)" ||
        fail "cannot read the entitlements of $file"
    if grep -Fq '<key>' <<<"$entitlements"; then
        fail "$file has an entitlement; the contract permits none"
    fi
    check_hygiene "$file"
}

# Check the license files of one directory: check_notices DIRECTORY.
check_notices() {
    local file
    for file in "${NOTICE_FILES[@]}"; do
        [ -s "$1/$file" ] || fail "$1/$file does not exist or is empty"
    done
    cmp -s "$1/LICENSE" "$ROOT/LICENSE" || fail "$1/LICENSE is not the LICENSE of the repository"
    head -n 1 "$1/THIRD_PARTY_LICENSES.txt" | grep -Fxq "Svalnir third-party software notices" ||
        fail "$1/THIRD_PARTY_LICENSES.txt does not start with the notice title"
}

# Print one value of Info.plist: plist_value KEY.
plist_value() {
    plutil -extract "$1" raw -o - "$APP/Contents/Info.plist"
}

# Fail when a value of Info.plist is not the expected one: plist_is KEY EXPECTED.
plist_is() {
    local value
    value="$(plist_value "$1")" || fail "Info.plist has no $1"
    [ "$value" = "$2" ] || fail "Info.plist has $1 '$value', not '$2'"
}

# Run the read-only commands of one directory of executables: check_run DIRECTORY.
# The home directory is empty and the state directory does not exist; the
# commands must leave them so.
check_run() {
    local dir="$1" home state output status
    home="$(mktemp -d "$WORK/home.XXXXXX")"
    state="$home.state"
    cli() {
        env -i PATH=/usr/bin:/bin HOME="$home" SVALNIR_STATE_DIR="$state" "$dir/svalnir" "$@"
    }
    output="$(cli --version)" || fail "'svalnir --version' failed in $dir"
    grep -Fq -- "$version" <<<"$output" || fail "'svalnir --version' printed '$output', without '$version'"
    output="$(cli license)" || fail "'svalnir license' failed in $dir"
    grep -Fq "GPL-3.0-only" <<<"$output" || fail "'svalnir license' did not name GPL-3.0-only"
    # `doctor` reports the capabilities of the host. Its exit status is 0 when
    # the report is complete, also when a capability is not available.
    status=0
    output="$(cli doctor 2>&1)" || status=$?
    [ "$status" -eq 0 ] || fail "'svalnir doctor' has the exit status $status in $dir: $(head -c 400 <<<"$output")"
    output="$(env -i PATH=/usr/bin:/bin HOME="$home" SVALNIR_STATE_DIR="$state" "$dir/svalnir-agent" --version)" ||
        fail "'svalnir-agent --version' failed in $dir"
    grep -Fq -- "$version" <<<"$output" || fail "'svalnir-agent --version' printed '$output', without '$version'"
    [ ! -e "$state" ] || fail "a read-only command made the state directory"
    [ -z "$(ls -A "$home")" ] || fail "a read-only command wrote into the home directory: $(ls -A "$home")"
}

step "files"
same_lines "the file list of $DIST" \
    "$(printf '%s\n' SHA256SUMS "$NAME-app.zip" "$NAME.tar.gz" | LC_ALL=C sort)" \
    "$(cd "$DIST" && find . -mindepth 1 -maxdepth 1 | sed 's:^\./::' | LC_ALL=C sort)"
same_lines "the file list of SHA256SUMS" \
    "$(printf '%s\n' "$NAME-app.zip" "$NAME.tar.gz" | LC_ALL=C sort)" \
    "$(awk '{ print $2 }' "$DIST/SHA256SUMS" | LC_ALL=C sort)"
(cd "$DIST" && shasum -a 256 --check --strict --quiet SHA256SUMS) || fail "SHA256SUMS does not agree with the artifacts"

step "layout"
same_lines "the binaries archive" \
    "$(archive_entries "$version")" \
    "$(tar -tzf "$ARCHIVE" | sed 's:/$::' | LC_ALL=C sort)"
same_lines "the application archive" \
    "$(if [ "$NOTARIZE" = "1" ]; then app_entries stapled; else app_entries; fi)" \
    "$(zipinfo -1 "$APP_ZIP" | sed 's:/$::' | LC_ALL=C sort)"
owners="$(tar -tvzf "$ARCHIVE" | awk '$3 != "0" || $4 != "0"')"
[ -z "$owners" ] || fail "an entry of the binaries archive does not have the owner 0 and the group 0"
mkdir "$WORK/archive" "$WORK/app"
tar -xzf "$ARCHIVE" -C "$WORK/archive"
unzip -q "$APP_ZIP" -d "$WORK/app"
readonly BIN_DIR="$WORK/archive/$NAME/bin"
readonly APP="$WORK/app/Svalnir.app"
readonly APP_BIN_DIR="$APP/Contents/MacOS"
links="$(find "$WORK/archive" "$WORK/app" -type l)"
[ -z "$links" ] || fail "an artifact has a symbolic link: $links"
modes="$(find "$WORK/archive/$NAME" "$APP" \( \( -type d ! -perm 755 \) -o \
    \( -type f ! -path '*/bin/*' ! -path '*/Contents/MacOS/*' ! -perm 644 \) \) -print)"
[ -z "$modes" ] || fail "an entry does not have the mode 755 (directory) or 644 (file): $modes"

step "code ($SIGNING)"
for bin in "${BINS[@]}"; do
    check_code "$BIN_DIR/$bin" "$bin"
    check_code "$APP_BIN_DIR/$bin" "$bin"
done
codesign --verify --strict --deep "$APP" || fail "Svalnir.app has no valid signature"
if [ "$NOTARIZE" = "1" ]; then
    xcrun stapler validate "$APP" || fail "Svalnir.app has no valid notarization ticket"
fi

step "notices"
check_notices "$WORK/archive/$NAME"
check_notices "$APP/Contents/Resources"
cmp -s "$WORK/archive/$NAME/THIRD_PARTY_LICENSES.txt" "$APP/Contents/Resources/THIRD_PARTY_LICENSES.txt" ||
    fail "the two artifacts have different third-party notices"

step "plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null || fail "Info.plist is not a property list"
plist_is CFBundleShortVersionString "$version"
plist_is CFBundleVersion "$version"
plist_is CFBundleIdentifier "$BUNDLE_ID"
plist_is CFBundleExecutable "$BUNDLE_EXECUTABLE"
plist_is CFBundlePackageType "APPL"
plist_is LSMinimumSystemVersion "$MIN_MACOS"
[ "$(cat "$APP/Contents/PkgInfo")" = "APPL????" ] || fail "PkgInfo is not 'APPL????'"
if grep -Eq '@[A-Z_]+@' "$APP/Contents/Info.plist"; then
    fail "Info.plist has a placeholder that the build did not replace"
fi
for plist in "$APP/Contents/Info.plist" "$APP/Contents/_CodeSignature/CodeResources"; do
    check_hygiene "$plist"
done

if [ "$run" -eq 1 ]; then
    step "run"
    check_run "$BIN_DIR"
    check_run "$APP_BIN_DIR"
else
    step "run (skipped)"
fi

echo "artifacts of $NAME agree with the layout contract" >&2
