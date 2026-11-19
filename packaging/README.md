# Packaging

This directory has the inputs of the macOS release artifacts. `scripts/package.sh` builds the artifacts into `dist/`, and `scripts/check-artifacts.sh` checks them. `scripts/package-layout.sh` is the layout contract in a form that the two scripts read. Keep this file and `scripts/package-layout.sh` the same.

The artifacts are development builds. They are not signed with a Developer ID and are not notarized, and no release gate of [VALIDATION.md](../docs/VALIDATION.md) is verified for them.

## Layout contract

The target is `aarch64-apple-darwin`, and the deployment target is macOS 13.0. `VERSION` is the workspace version in `Cargo.toml`.

`svalnir-VERSION-aarch64-apple-darwin.tar.gz`:

```text
svalnir-VERSION-aarch64-apple-darwin/
├── LICENSE
├── README.md
├── THIRD_PARTY_LICENSES.txt
└── bin/
    ├── svalnir
    ├── svalnir-agent
    ├── svalnir-gui
    └── svalnir-privileged
```

`svalnir-VERSION-aarch64-apple-darwin-app.zip`:

```text
Svalnir.app/
└── Contents/
    ├── Info.plist
    ├── PkgInfo
    ├── MacOS/
    │   ├── svalnir
    │   ├── svalnir-agent
    │   ├── svalnir-gui
    │   └── svalnir-privileged
    ├── Resources/
    │   ├── LICENSE
    │   └── THIRD_PARTY_LICENSES.txt
    └── _CodeSignature/
        └── CodeResources
```

A notarized bundle also has `Contents/CodeResources`, the ticket that `stapler` adds.

`SHA256SUMS` has the SHA-256 sum of the two archives.

The rules of the contract:

- Each artifact has exactly these entries. `scripts/check-artifacts.sh` fails for a missing entry and for an entry that is not in the list.
- The four executables are in one directory. Thus the `svalnir-agent` executable is beside the `svalnir` executable in each artifact, which the service commands of the CLI require.
- No entry is a symbolic link. Each executable is a regular file with the mode 755, and each directory has the mode 755. Each other file has the mode 644.
- `CFBundleExecutable` is `svalnir-gui`. The other three executables are nested code of the bundle.
- `CFBundleShortVersionString` and `CFBundleVersion` are `VERSION`. `LSMinimumSystemVersion` is the deployment target of each executable.
- Each executable has no path of the build host and no environment variable name that starts with `SVALNIR_TEST_`.

## Code identifiers and entitlements

| Executable | Identifier | Entitlements file |
| --- | --- | --- |
| `svalnir` | `dev.po4yka.svalnir.cli` | `macos/entitlements/svalnir.entitlements` |
| `svalnir-agent` | `dev.po4yka.svalnir.agent` | `macos/entitlements/svalnir-agent.entitlements` |
| `svalnir-privileged` | `dev.po4yka.svalnir.privileged` | `macos/entitlements/svalnir-privileged.entitlements` |
| `svalnir-gui`, `Svalnir.app` | `dev.po4yka.svalnir` | `macos/entitlements/svalnir-gui.entitlements` |

Each entitlements file is an empty dictionary. No executable needs an exception of the hardened runtime, and no executable uses the App Sandbox. Before you add a key, record the reason in this section. `scripts/check-artifacts.sh` fails when a signed executable has an entitlement.

## Signing

`scripts/package.sh` signs in this order:

1. Each executable of the binaries archive, as single code.
2. Each nested executable in `Svalnir.app/Contents/MacOS`: `svalnir`, `svalnir-agent`, `svalnir-privileged`.
3. `Svalnir.app`. This signature covers `svalnir-gui`, and it seals the nested code, `Info.plist`, and `Resources`. No file of the bundle changes after this step, except for the stapled ticket.

Each signature has the hardened runtime (`--options runtime`) and the entitlements file of the executable.

| `SVALNIR_SIGNING` | Signature |
| --- | --- |
| `adhoc`, the default | Ad hoc, with no timestamp. Gatekeeper blocks the application after a download. |
| `developer-id` | The identity that `SVALNIR_SIGN_IDENTITY` names, with a secure timestamp. The script stops before the build when the variable is empty or when no valid `Developer ID Application` identity with that name is in the keychain search list. |

`SVALNIR_NOTARIZE=1` sends the application and the executables to the Apple notary service with the keychain profile that `SVALNIR_NOTARY_PROFILE` names, staples the ticket to `Svalnir.app`, and validates it. It needs `developer-id` signing. A ticket cannot be stapled to a single executable, so Gatekeeper gets the ticket of the binaries archive online.

The `developer-id` and notarization steps were not run: the project has no Developer ID.

## Reproducible content

For one commit, one toolchain, and one build host, two runs of `scripts/package.sh` make the same bytes:

- Each archive entry has the time `SOURCE_DATE_EPOCH`. The default is the committer time of `HEAD`.
- The entries are in the order of `LC_ALL=C sort`, with fixed modes. The tar entries have the owner 0 and the group 0. The gzip header has no name and no time. The zip entries have no extra field.
- The build replaces the path of the checkout, of the Cargo home, and of the home directory in the executables (`--remap-path-prefix`).
- An ad-hoc signature has no timestamp. A Developer ID signature has one, so a signed artifact is not the same for two runs.

The sameness of the executables for two build hosts is not verified.
