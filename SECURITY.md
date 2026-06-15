# Security Policy

## Supported Versions

Hushbox is under active development.

Security fixes are applied to the latest development version unless stated otherwise.

| Version | Supported |
|---------|-----------|
| Latest  | Yes |
| Older releases | No |

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Instead, report them privately by contacting the maintainer through the security contact below.

- Security contact: `security@bevirtual.cloud`

Please include:

- A clear description of the issue.
- Steps to reproduce the problem.
- A proof of concept, if available.
- The affected version or commit hash.
- Any suggested mitigation, if known.

## Response Expectations

The goal is to acknowledge new reports within 7 days and provide a status update after initial triage.

If the report is valid, a fix will be prepared and released as soon as reasonably possible. Please allow time for investigation and coordinated disclosure.

## Scope

This policy covers:

- The desktop client.
- The relay server.
- Documentation that may expose insecure defaults or misleading security assumptions.

## Operational Notes

Hushbox uses end-to-end encryption for message content, but deployment security still depends on:

- Safe private key storage.
- Out-of-band public key verification.
- TLS protection for relay access.
- Secure relay hosting and log handling.
- Reasonable message retention settings.