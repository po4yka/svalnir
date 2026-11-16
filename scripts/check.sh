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
#   pins       agent skills: gpui-kit skill revision and the .agents/skills links
#
# Cargo commands that resolve dependencies use --locked. The script does not
# change files.

set -euo pipefail

cd "$(dirname "$0")/.."

readonly ALL_STEPS=(fmt clippy test doc deny typos links workflows shell pins)

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

# Check that the gpui-kit skills are at the tag of the gpui-kit dependency, and
# that .agents/skills has one link for each skill in .claude/skills.
check_pins() {
    local version skill name
    version="$(sed -n 's/^gpui-kit = "=\(.*\)"$/\1/p' Cargo.toml)"
    if [ -z "$version" ]; then
        echo "error: Cargo.toml has no exact gpui-kit requirement" >&2
        return 1
    fi
    for skill in gpui-kit gpui-kit-design-guides; do
        if ! grep -q "^    github-pinned: v${version}\$" ".claude/skills/$skill/SKILL.md"; then
            echo "error: skill '$skill' is not pinned to v${version}; see \"Agent skills\" in AGENTS.md" >&2
            return 1
        fi
    done
    for skill in .claude/skills/*/; do
        name="$(basename "$skill")"
        if [ "$(readlink ".agents/skills/$name")" != "../../.claude/skills/$name" ]; then
            echo "error: .agents/skills/$name is not a link to the skill in .claude/skills" >&2
            return 1
        fi
    done
    for skill in .agents/skills/*; do
        if [ ! -f "$skill/SKILL.md" ]; then
            echo "error: $skill does not resolve to a skill" >&2
            return 1
        fi
    done
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
    pins)
        check_pins
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
