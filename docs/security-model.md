# Security Model

## Overview

Hushbox uses end-to-end encryption for message content.

Messages are encrypted on the sender’s device and decrypted on the recipient’s device. The relay is not involved in cryptographic operations.

## Cryptographic Model

The client uses NaCl/libsodium public-key authenticated encryption.

Private keys are generated locally and should never leave the device.

## What the Relay Can See

The relay may see:

- recipient queue identifiers,
- optional sender identifiers,
- encrypted payloads,
- timestamps,
- message size,
- polling and delivery activity.

The relay cannot decrypt message content.

## What Hushbox Does Not Hide

Hushbox does not eliminate all metadata exposure.

Depending on deployment and usage, operators may still infer:

- when messages are submitted,
- when recipients poll the relay,
- how often users communicate,
- approximate payload sizes.

## Operational Recommendations

For higher-sensitivity environments:

- self-host the relay,
- protect it with HTTPS,
- minimize retention time,
- verify public keys out of band,
- secure client devices,
- keep logs to a minimum.

## Trust Assumptions

Users must trust:

- the local client environment,
- the integrity of distributed binaries or source code,
- their method of public key verification,
- the relay operator not to tamper with availability, even though the relay cannot read plaintext.

## Non-Goals

Hushbox is not designed to provide:

- anonymous network routing,
- traffic analysis resistance,
- endpoint compromise protection,
- deniability beyond what the underlying cryptographic construction provides.