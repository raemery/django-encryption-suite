# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately by email to
**encryption-suite@protonmail.com**. Do not open a public issue, pull request,
or discussion for a vulnerability.

Include:

- The package version, the crypto backend, and the KMS adapter you use.
- A description of the problem and what an attacker could do with it.
- Steps or a minimal test that reproduce it.

Do not send live credentials, key material, or production data. Describe the
shape of the data instead.

Coordinate disclosure with the maintainer before publishing details, so a fix
can ship first.

## Supported versions

Security fixes are released for the latest version of the package only. Upgrade
to it to receive them.

## Scope

In scope: the code in `src/encryption_suite`, including the silo and key store
adapters, the crypto backends, the view helpers, and the admin screens.

Out of scope: your application's own code, the configuration of your
deployment, and the KMS provider's service. Report problems in a KMS provider to
that provider.

Behavior that [Security model](docs/security.md) states as a limit is a design
limit, not a vulnerability. A report showing that the documentation is wrong
about that behavior is still welcome.
