# Contributing

Solo personal repository. No CODEOWNERS, no ticket tracker integration, no
automated release process — this file just records the conventions actually
in effect.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
(`feat:`, `fix:`, `docs:`, `chore:`, etc.) are used for readability, not
enforced by tooling and not tied to an automated changelog generator —
CHANGELOG.md files were removed along with release-please; see the
per-directory git history instead.

## Before committing

`pre-commit install` (see `.pre-commit-config.yaml`) runs YAML/markdown
hygiene, Helm lint/unittest, the Go gates (`go fmt`/`vet`/`golangci-lint`/
`go mod tidy`/`go test`) for `ci/private-pki-operator`, and secret scanning.
`govulncheck` runs at `pre-push` only (needs network access).

## Pull requests

No fixed template. Explain what changed and why; link any relevant issue.
CI (`.github/workflows/build.yml`, `trufflehog.yaml`) must pass.

## Documentation

`docs/` holds ADRs, design plans, and the operator manual/user guide for
`private-pki-operator`. Keep them in sync with code changes that affect
their content, but there's no enforced structure beyond what's already
there.
