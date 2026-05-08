# Security Policy

## Reporting a vulnerability

If you've found a security issue in Fira, please report it privately
rather than opening a public GitHub issue.

Email **scrimix@gmail.com** with:

- A description of the issue and the impact you think it has
- Steps to reproduce (or a proof-of-concept)
- The commit / version you tested against
- Whether you'd like to be credited in the fix announcement

I'll acknowledge the report within a few days and keep you in the
loop as I investigate. Please give me a reasonable window to ship a
fix before disclosing publicly.

## Scope

In scope:

- The Fira API (`api/`) and web app (`web/`) in this repository
- The hosted instance at <https://usefira.app>

Out of scope:

- Findings that require physical access to a user's device
- Social engineering of Fira users or the maintainer
- Denial-of-service via raw traffic volume
- Vulnerabilities in third-party dependencies that don't affect Fira's
  actual usage of them — please report those upstream

Fira is a hobby/open-source project with no bug bounty, but I'm
genuinely grateful for responsible disclosure and will credit
reporters who want it.
