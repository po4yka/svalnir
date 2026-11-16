# Third-party notices

This file records the material that the repository imports from other projects, as [CONTRIBUTING.md](CONTRIBUTING.md#handle-dependencies-licensing-and-provenance) specifies. The licenses of the Cargo dependencies are not listed here; `scripts/package.sh` generates `THIRD_PARTY_LICENSES.txt` for them.

## rust-skills

| Item | Value |
| --- | --- |
| Upstream repository | <https://github.com/po4yka/rust-skills> |
| Revision | Tag `v0.5.0`, commit `0d0b9462c8f51532253af6e20458d934b24c8bf7` |
| Upstream paths | `skills/<name>/` for each of the 27 skills below |
| Location in this repository | `.claude/skills/<name>/`. Each `.agents/skills/<name>` is a symbolic link to that directory. |
| License | BSD-3-Clause |
| Use | Reference sheets that a coding agent loads during development. They are not part of a Svalnir binary or release artifact. |
| Modifications | `gh skill install` added source-tracking metadata (`github-repo`, `github-ref`, `github-pinned`, `github-path`, `github-tree-sha`) to the frontmatter of each `SKILL.md`. No other change. |

Imported skills: `cargo-workflows`, `memory-model`, `rust-allocators`, `rust-async-internals`, `rust-cli`, `rust-code-style`, `rust-compiler-errors`, `rust-crate-architecture`, `rust-crate-release`, `rust-debugging`, `rust-discipline`, `rust-error-handling`, `rust-event-loop-state`, `rust-lints`, `rust-native-linking`, `rust-observability`, `rust-panic-safety`, `rust-performance`, `rust-pin-projection`, `rust-port`, `rust-review`, `rust-sanitizers-miri`, `rust-security`, `rust-send-sync`, `rust-tdd`, `rust-test-tools`, `rust-unsafe`.

License text:

```text
BSD 3-Clause License

Copyright (c) 2026, Nikita Pochaev

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
