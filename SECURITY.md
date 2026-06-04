# Security Policy

shipgrade is a command-line tool that audits an LLM feature for product-safety and
regulated-domain compliance. This policy covers the security of the shipgrade tool itself.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x (latest) | yes           |
| < latest 0.x | no            |

shipgrade is pre-1.0. Only the latest 0.x release receives security fixes, and breaking
changes are allowed on minor version bumps while the version is 0.x.

## Reporting a vulnerability

Report a security vulnerability privately. Do not open a public issue.

Use GitHub Security Advisories: open the repository Security tab and click "Report a
vulnerability", or go directly to
https://github.com/RivetaLabs/shipgrade/security/advisories/new.

shipgrade is maintained by one person. Expect an initial response within 7 days. There is
no paid support tier and no guaranteed patch timeline.

## Scope

In scope: a vulnerability in the shipgrade tool. Examples are server-side request forgery
through the HTTP adapter, a secret or PII leak into a generated report, an unescaped target
response rendered in the HTML report, and arbitrary code execution outside the documented
callable-adapter contract.

Out of scope: the findings shipgrade reports about your own LLM feature. A low grade on your
target is shipgrade working as intended, not a vulnerability in shipgrade.

The callable adapter runs your own Python in-process by design. Pointing it at untrusted or
remote code is outside the supported use, not a shipgrade vulnerability.

## How shipgrade handles sensitive data

shipgrade redacts secrets and PII in evidence before any output. Detection and redaction
happen locally, immediately after a target response is captured, and before the response
reaches the LLM judge or any report.

Provider API keys are read from the process environment only. They are never logged, never
written to a report, and never sent to the judge.

The offline demo and any `--offline` run send nothing over the network.

## Verifying a release

shipgrade publishes to PyPI through Trusted Publishing with PEP 740 build attestations. To
verify a downloaded wheel against its provenance, run:

```bash
gh attestation verify <wheel> --repo RivetaLabs/shipgrade
```

This verifies the published wheel against its PEP 740 build provenance: GitHub OIDC
identity, the Sigstore transparency log, and PyPI provenance, with no long-lived token in
the release.

## Note

shipgrade is a portfolio project maintained by Jacob Dennis (RivetaLabs). Responses may be
slow.
