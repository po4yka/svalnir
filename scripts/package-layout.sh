# shellcheck shell=bash
# The layout contract of the macOS release artifacts.
#
# scripts/package.sh and scripts/check-artifacts.sh read this file with
# `source`. It defines names only and runs no command. packaging/README.md
# describes the contract; keep the two the same.
#
# The scripts that read this file use the names, so ShellCheck sees no use here.
# shellcheck disable=SC2034

# The Rust target of the artifacts.
readonly TARGET="aarch64-apple-darwin"
# The architecture name that `lipo -archs` prints for TARGET.
readonly MACHO_ARCH="arm64"
# The bundle identifier of Svalnir.app and the prefix of each code identifier.
readonly BUNDLE_ID="dev.po4yka.svalnir"
# The deployment target of each executable and LSMinimumSystemVersion.
readonly MIN_MACOS="13.0"
# The executable that CFBundleExecutable names.
readonly BUNDLE_EXECUTABLE="svalnir-gui"
# Each executable of an artifact. All of them are in one directory, so the
# `svalnir-agent` executable is beside the `svalnir` executable.
readonly BINS=(svalnir svalnir-agent svalnir-privileged svalnir-gui)
# The license files of an artifact.
readonly NOTICE_FILES=(LICENSE THIRD_PARTY_LICENSES.txt)

# Print the code-signing identifier of an executable.
code_identifier() {
    case "$1" in
    svalnir) echo "$BUNDLE_ID.cli" ;;
    svalnir-agent) echo "$BUNDLE_ID.agent" ;;
    svalnir-privileged) echo "$BUNDLE_ID.privileged" ;;
    svalnir-gui) echo "$BUNDLE_ID" ;;
    *) return 1 ;;
    esac
}

# Print the base name of the artifacts of a version.
artifact_name() {
    echo "svalnir-$1-$TARGET"
}

# Print each entry of the binaries archive of a version, in the order of
# `LC_ALL=C sort`. A directory has no trailing slash.
archive_entries() {
    local name bin
    name="$(artifact_name "$1")"
    {
        echo "$name"
        echo "$name/LICENSE"
        echo "$name/README.md"
        echo "$name/THIRD_PARTY_LICENSES.txt"
        echo "$name/bin"
        for bin in "${BINS[@]}"; do
            echo "$name/bin/$bin"
        done
    } | LC_ALL=C sort
}

# Print each entry of the application archive, in the order of
# `LC_ALL=C sort`. A directory has no trailing slash. With the argument
# "stapled", the list has the notarization ticket that `stapler` adds.
app_entries() {
    local bin
    {
        if [ "${1:-}" = "stapled" ]; then
            echo "Svalnir.app/Contents/CodeResources"
        fi
        echo "Svalnir.app"
        echo "Svalnir.app/Contents"
        echo "Svalnir.app/Contents/Info.plist"
        echo "Svalnir.app/Contents/PkgInfo"
        echo "Svalnir.app/Contents/MacOS"
        for bin in "${BINS[@]}"; do
            echo "Svalnir.app/Contents/MacOS/$bin"
        done
        echo "Svalnir.app/Contents/Resources"
        echo "Svalnir.app/Contents/Resources/LICENSE"
        echo "Svalnir.app/Contents/Resources/THIRD_PARTY_LICENSES.txt"
        echo "Svalnir.app/Contents/_CodeSignature"
        echo "Svalnir.app/Contents/_CodeSignature/CodeResources"
    } | LC_ALL=C sort
}
