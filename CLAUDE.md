# CLAUDE.md

The shared repository rules are in `AGENTS.md`, imported below. This file adds only what is specific to Claude Code sessions; a rule that applies to all agents belongs in `AGENTS.md`.

@AGENTS.md

## Select the check

For a document-only change, the check is the consistency check in "Edit the specifications". For a code change, use the command menu in `AGENTS.md` with the packages that `cargo metadata` reports.

## Read the specifications in sections

`README.md` and each file in `docs/` are 30 KB to 65 KB. List the headings, then read the section that answers the question:

```sh
rg -n '^#{2,3} ' docs/POLICY_SPEC.md
```

Start from the "Design specifications" table in `README.md` to find the document that owns a subject.

## Edit the specifications

1. Change the owning specification first. Then search for the same term in the other documents and align each occurrence in the same change:

   ```sh
   rg -n 'TERM' README.md AGENTS.md CONTRIBUTING.md DESIGN.md docs/
   ```

2. Keep the stable identifiers unchanged: threats `T-01` to `T-15`, validation families `VAL-01` to `VAL-16`, release gates `G-01` to `G-09`, rule IDs, action-class names, and operation-state names. To retire one, keep its number reserved.
3. Write each requirement as planned behavior. A statement that something passes, ships, or is verified needs recorded evidence under `docs/VALIDATION.md`.
4. Name the untracked `PROJECT_REFERENCES.md` as plain text only. A link to it from a tracked document is broken for other contributors.
5. Finish with the consistency check. The change is complete when all of these are true:
   - Each relative link and heading anchor resolves.
   - Each reference-style link has one definition, and each definition is used.
   - Each code fence is closed, and each Mermaid block has valid syntax.
   - Each section-number cross-reference points to the intended section.
   - The search in step 1 shows no occurrence that contradicts the owning specification.

## GUI work

Read the sections of `DESIGN.md` that cover the view before a change to `crates/svalnir-gui`.

To check a view, run the application and take a screenshot in the two themes and with Reduce Motion on. A successful build does not show that a view agrees with `DESIGN.md`.

## Rust skills

`.claude/skills/` holds 27 skills from `po4yka/rust-skills`, pinned to the tag `v0.5.0`. Do not edit these files. To move to a newer tag, install each skill again with the new tag, then update `THIRD_PARTY_NOTICES.md`:

```sh
gh skill install po4yka/rust-skills skills/NAME --pin TAG --agent claude-code --scope project --force
```

## Subagents

Use one writer for the documents. They cross-reference each other, so parallel edits to different files produce contradictions. Read-only search and review can run in parallel.

## Local files

Put personal instructions in `CLAUDE.local.md` and personal settings in `.claude/settings.local.json`. Git ignores both files.
