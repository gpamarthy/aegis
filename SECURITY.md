# Security policy

## Supported versions

Pre-1.0, only the latest tagged release receives security fixes.

## Reporting a vulnerability

**Do not file public issues for security problems.**

Email a description and reproduction to the maintainer. Expect an acknowledgement within 72 hours and a fix or mitigation plan within 14 days for issues that can be reproduced.

If no response in 14 days, you are free to disclose publicly.

## Scope

In scope:

- Vulnerabilities in the scanner itself (RCE in scanner code, credential leakage in reports, path traversal in HTML output)
- False negatives where a real LLM vulnerability is missed by an existing scanner
- Auth or credential mishandling in connectors

Out of scope:

- Vulnerabilities in the LLM endpoints being scanned. Report those to the LLM vendor.
- Behavioral findings against scanned targets. Those are the product's purpose.
- Vulnerabilities in `litellm`, `pydantic`, or other upstream dependencies. Report to the respective project.

## Disclosure handling

Reports are handled confidentially. Reporter credit in CHANGELOG and release notes if requested.
