#!/usr/bin/env bash
# Run the repository static checks.
#
# Usage: scripts/check.sh [STEP...]
# With no STEP, run all steps in order. Steps:
#   fmt        rustfmt formatting
#   clippy     Clippy on all targets, warnings are errors
#   test       workspace tests
#   doc        rustdoc, warnings are errors
#   deny       cargo-deny: advisories, licenses, bans, sources
#   typos      spelling in code and documents
#   links      relative links and heading anchors in Markdown (offline)
#   workflows  actionlint and zizmor on GitHub Actions workflows
#   shell      shellcheck on shell scripts
#
# Cargo commands that resolve dependencies use --locked. The script does not
# change files.

set -euo pipefail

cd "$(dirname "$0")/.."

readonly ALL_STEPS=(fmt clippy test doc deny typos links workflows shell)

require() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: '$tool' is not installed; see CONTRIBUTING.md#static-checks" >&2
        exit 127
    fi
}

# Print tracked and untracked, not ignored files that match the pathspecs, NUL-separated.
repo_files() {
    git ls-files -z --cached --others --exclude-standard -- "$@"
}

run_step() {
    case "$1" in
    fmt)
        cargo fmt --all --check
        ;;
    clippy)
        cargo clippy --workspace --all-targets --locked -- -D warnings
        ;;
    test)
        cargo test --workspace --locked
        ;;
    doc)
        RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
        ;;
    deny)
        require cargo-deny
        cargo deny --locked check
        ;;
    typos)
        require typos
        typos
        ;;
    links)
        require lychee
        repo_files '*.md' ':(exclude).claude/skills' | xargs -0 -r lychee --config lychee.toml --
        ;;
    workflows)
        require actionlint
        require zizmor
        actionlint
        zizmor --offline --pedantic .github/
        ;;
    shell)
        require shellcheck
        repo_files '*.sh' | xargs -0 -r shellcheck --
        ;;
    *)
        echo "error: unknown step '$1'; steps: ${ALL_STEPS[*]}" >&2
        exit 2
        ;;
    esac
}

if [ "$#" -eq 0 ]; then
    set -- "${ALL_STEPS[@]}"
fi

for step in "$@"; do
    echo "==> $step" >&2
    run_step "$step"
done
