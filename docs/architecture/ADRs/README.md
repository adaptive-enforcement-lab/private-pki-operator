# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for this repository. Each ADR captures a significant architectural decision, its context, the alternatives considered, and the rationale for the choice made.

## Format

ADRs use the following frontmatter:

```yaml
---
date: YYYY-MM-DD
status: Accepted | Superseded by DEC-XXX | Deprecated
category: Architecture | Security | Technical | Operations
version: 0.1.0
decision_driver:
  name: [Name]
  email: [email]
  title: [Role]
---
```

## Status definitions

| Status | Meaning |
|--------|---------|
| `Accepted` | Decision is current and in effect |
| `Superseded by DEC-XXX` | A later decision replaced this one |
| `Deprecated` | Decision is no longer relevant but retained for history |

## Index

| ID | Date | Title | Status | Category |
|----|------|-------|--------|---------|
| [DEC-002](./DEC-002-private-pki-operator.md) | 2026-03-01 | private-pki-operator — Kubernetes Operator for Automated Safe Root CA Rotation | Accepted | Architecture |
