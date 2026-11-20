# Fuzz harnesses

This directory has the fuzz harnesses of the validation family VAL-14 in [docs/VALIDATION.md](../docs/VALIDATION.md#val-14--parsing-concurrency-and-native-boundaries). It is a `cargo-fuzz` crate with its own workspace and its own `Cargo.lock`. It is not a member of the root workspace, so `scripts/check.sh` does not build it, and it is not part of a release artifact.

## Targets

| Target | Decoder | Properties |
| --- | --- | --- |
| `config_parse` | `svalnir_core::config::parse_and_validate` | No panic. Two calls on the same text give the same result. A validated configuration has no findings. |
| `plan_document` | `Plan` and `PlanOutcome` of `svalnir-core`, decoded with `serde_json` | No panic. A decoded value encodes and decodes to the same value. |
| `journal_records` | The record types that the journal of `svalnir-agent` decodes: `Operation`, `Step`, `RequestEnvelope`, `Principal`, `ActionError`, `QueuedRequest`, `RequestCompletion` | No panic. A decoded value encodes and decodes to the same value. |
| `helper_request` | `svalnir_privileged::request::decode_request` | No panic. The encoding of an accepted request is accepted and gives the same request. |
| `helper_response` | `svalnir_privileged::response::decode_response` | No panic. An encoded response decodes to the same response. |
| `grammars` | `parse_duration` and `parse_byte_size` of `svalnir-core` | No panic. An accepted value has the same value in `ms` or in `B`. |

The private decoders of the journal read their text from an SQLite row, so no target calls them directly. The `journal_records` target decodes the same types with the same `serde_json` call.

## Seed corpora

`seeds/TARGET/` has the seed inputs of each target. The JSON seeds are the `serde_json` encodings of the sample values of the unit tests of `svalnir-core` and `svalnir-privileged`. The configuration seeds are copies of `crates/svalnir-cli/fixtures/`.

## Run a target

The commands need `cargo-fuzz` 0.13 and a nightly toolchain. Give the target triple: without it, a `cargo-fuzz` binary for `x86_64` builds for `x86_64-apple-darwin`. Put the working corpus and the artifacts outside the seed directory, so a run does not change `seeds/`:

```sh
cd fuzz
cargo +nightly fuzz build --target aarch64-apple-darwin
mkdir -p corpus/config_parse artifacts/config_parse
cargo +nightly fuzz run --target aarch64-apple-darwin config_parse \
    corpus/config_parse seeds/config_parse -- \
    -max_total_time=60 -rss_limit_mb=2048 -timeout=10 -max_len=65536 \
    -artifact_prefix=artifacts/config_parse/
```

The limits are the input, time, and memory limits that VAL-14 requires. `corpus/` and `artifacts/` are ignored by Git. To reproduce a failure, give the artifact file in the place of the corpus directories.

A fuzz run is not recorded evidence for VAL-14 until `docs/VALIDATION.md` records it.
