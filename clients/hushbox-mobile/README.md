# hushbox-mobile

> **Placeholder** — implementation planned for a future milestone.

Mobile client for Hushbox — end-to-end encrypted messaging using the same `hushbox-core` package and relay protocol as the desktop client.

## Planned architecture

### Core library integration

The mobile client will reuse `hushbox-core` in one of two ways:

- **Python runtime** (preferred for prototyping): [Kivy](https://kivy.org/) or [BeeWare/Briefcase](https://beeware.org/) can ship a full CPython interpreter, allowing `hushbox-core` to be imported directly — no porting required.
- **Native via FFI**: For a fully native iOS/Android app, the cryptographic and protocol logic from `hushbox-core` can be exposed through a C-compatible FFI layer (e.g. `cffi` + shared library), consumed by Swift or Kotlin.

### Relay API

The relay server exposes a versioned REST API (`/v1/`). The mobile client will use the same `v1` endpoints as the desktop client — no protocol changes are required on the server side.

### Key storage

Private keys are never stored in plain files on mobile:

- **iOS**: keys are stored in the system **Keychain** (`kSecClassKey` item class).
- **Android**: keys are stored in the **Android Keystore** system, optionally backed by hardware security module (StrongBox).

## Status

This directory is a placeholder. No implementation exists yet. See `ROADMAP.md` for the planned milestones.
