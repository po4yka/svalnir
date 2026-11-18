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

## gpui-kit skills

| Item | Value |
| --- | --- |
| Upstream repository | <https://github.com/longbridge/gpui-kit> |
| Revision | Tag `v0.10.0`, commit `f697c3133d55c64fa8a5b67926147fb3dadd276d` |
| Upstream paths | `skills/gpui-kit/`, `skills/gpui-kit-design-guides/` |
| Location in this repository | `.claude/skills/gpui-kit/`, `.claude/skills/gpui-kit-design-guides/`, and a symbolic link to each in `.agents/skills/` |
| License | Apache-2.0. Copyright 2024 - 2026 Longbridge. The text is in [LICENSES/gpui-kit-Apache-2.0.txt](LICENSES/gpui-kit-Apache-2.0.txt). |
| Use | Reference sheets that a coding agent loads during development. They are not part of a Svalnir binary or release artifact. |
| Modifications | `gh skill install` added source-tracking metadata to the frontmatter of each `SKILL.md`. No other change. |

The `gpui-kit` crate is a Cargo dependency, not imported source. `THIRD_PARTY_LICENSES.txt` covers it.

## Zed skills

| Item | Value |
| --- | --- |
| Upstream repository | <https://github.com/zed-industries/zed> |
| Revision | Commit `7b5cc722a13192533a01c88800c75b22f5b1d5e6` |
| Upstream paths | `.agents/skills/gpui-test/`, `.agents/skills/gpui-bench/` |
| Location in this repository | `.claude/skills/gpui-test/`, `.claude/skills/gpui-bench/`, and a symbolic link to each in `.agents/skills/` |
| License | GPL-3.0-or-later. The Zed README states that the source is "licensed primarily under GPL-3.0-or-later, with Apache-2.0 components where marked"; these files have no Apache-2.0 mark. The GPL version 3 text is in [LICENSE](LICENSE). |
| Use | Reference sheets that a coding agent loads during development. They are not part of a Svalnir binary or release artifact. |
| Modifications | `gh skill install` added source-tracking metadata to the frontmatter of each `SKILL.md` on 2026-11-16. No other change. |

## Geist and Geist Mono

| Item | Value |
| --- | --- |
| Upstream repository | <https://github.com/vercel/geist-font> |
| Revision | Release `v1.9.2`, file `geist-font-v1.9.2.zip` |
| Upstream paths | `geist-font/Geist/ttf/Geist-{Regular,Medium,SemiBold}.ttf`, `geist-font/GeistMono/ttf/GeistMono-{Regular,Medium}.ttf`, `geist-font/OFL.txt` |
| Location in this repository | `crates/svalnir-gui/assets/fonts/` |
| License | SIL Open Font License 1.1 |
| Use | The `svalnir-gui` binary embeds the five font files and registers them at the start. |
| Modifications | None |

License text:

```text
Copyright 2026 The Geist Project Authors (https://github.com/vercel/geist-font)

This Font Software is licensed under the SIL Open Font License, Version 1.1.
This license is copied below, and is also available with a FAQ at:
https://openfontlicense.org


-----------------------------------------------------------
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded, 
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```
