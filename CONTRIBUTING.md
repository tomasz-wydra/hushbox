# Contributing

Thanks for your interest in contributing to Hushbox.

Contributions are welcome in the form of code, bug reports, documentation improvements, test coverage, and security hardening suggestions.

## Ways to Contribute

- Report bugs.
- Improve documentation.
- Add or refine tests.
- Propose UX improvements.
- Suggest relay hardening or deployment improvements.
- Submit code changes.

## Before You Start

Please open an issue before starting major work so the scope and direction can be discussed first.

For security vulnerabilities, do not use public issues. See [SECURITY.md](./SECURITY.md).

## Development Setup

### Client

```bash
pip install -r requirements.txt
python main.py
```

### Relay server

```bash
cd relay_server
docker compose up -d
```

## Running Tests

### Client tests

```bash
python -m pytest tests/ -v
```

### Relay server tests

```bash
cd relay_server
pip install flask pytest
python -m pytest tests/ -v
```

## Pull Request Guidelines

- Keep pull requests focused and reasonably small.
- Include tests when changing behavior.
- Update documentation when changing setup, configuration, or user flows.
- Prefer clear commit messages and descriptive PR titles.
- Avoid unrelated refactors in the same pull request.

## Coding Guidelines

- Prefer readable, explicit code over clever shortcuts.
- Keep security-sensitive logic simple and easy to review.
- Do not introduce cryptographic changes without a clear rationale and tests.
- Preserve backward compatibility where possible, or document breaking changes clearly.

## Documentation Guidelines

If you change:

- setup steps,
- API behavior,
- configuration,
- file layout,
- security assumptions,

please update the relevant file in `docs/` as part of the same change.

## Questions

If something is unclear, open an issue describing:

- what you are trying to do,
- what you expected,
- what happened instead.