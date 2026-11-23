# Contributing to Hushbox

Thanks for your interest in improving Hushbox. This document explains the one formal requirement for contributions and a few practical rules.

## Developer Certificate of Origin (DCO)

Every commit in a pull request must be signed off. By adding a sign-off you certify that you agree to the [Developer Certificate of Origin, version 1.1](https://developercertificate.org/). In short, you confirm that:

1. you wrote the change yourself, or you have the right to submit it under the license of the part of the repository it touches;
2. if the change is based on someone else's work, that work is covered by a compatible open-source license and you are allowed to submit it;
3. you understand that the contribution and your sign-off (including your name and email) are public and will be kept as part of the project history.

The full, binding text is the one published at <https://developercertificate.org/>.

### How to sign off

Add `-s` when committing:

```bash
git commit -s -m "Describe your change"
```

Git appends a line like this to the commit message:

```
Signed-off-by: Jane Doe <jane@example.com>
```

The name and email must match the commit author. Anonymous or pseudonymous sign-offs are not accepted.

Forgot to sign off? Fix the last commit with `git commit --amend -s --no-edit`, or all commits on your branch with `git rebase --signoff main`, then force-push the branch.

Pull requests from forks are checked automatically by the **DCO** workflow. A pull request with unsigned commits will not be merged.

## Licensing of contributions

Contributions are accepted under the license of the directory they change ("inbound = outbound"):

| Path | License |
|------|---------|
| `packages/hushbox-core/` | Apache License 2.0 |
| `services/hushbox-relay-api/` | MIT |
| `clients/hushbox-web/` | MIT |

Do not add code copied from projects under incompatible licenses (for example GPL code into the Apache-2.0 or MIT parts).

## Security issues

Do not report vulnerabilities in public issues or pull requests. Contact the maintainer privately through GitHub (repository **Security** tab → **Report a vulnerability**). Details, scope and response times are in [SECURITY.md](SECURITY.md).

## Practical rules

- Keep pull requests focused: one logical change per pull request.
- Changes to the wire format, key file format or cryptography in `hushbox-core` need a short description of the reasoning and tests that cover the new behaviour.
- Run the tests before opening a pull request:

  ```bash
  pip install -e "packages/hushbox-core[dev]"
  pytest packages/hushbox-core/tests/ -v
  pytest services/hushbox-relay-api/tests/ -v
  ```
