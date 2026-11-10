# Understanding the code base

This page maps the package's pluggable layers to the folders that hold them,
and traces how a value moves through those layers on encrypt and decrypt.

## Adapters

Everything under `adapters/` is an *adapter*: a pluggable component selected
via the `ENCRYPTION` setting, implementing an abstract base, and wired by the
registry. The package is split by concern:

- `silos/`: resolves the current runtime silo (group of data that shares key
  isolation) and turns it into stable identifiers (`silo_uid`, silo label). There
  is one silo adapter per distinct adapter in `KEY_SETS`, shared by the key sets bound to it; a silo's
  keys are identified by their key set and the adapter's raw uid. Implementations for generic
  Django models, SaaS Pegasus teams, django-tenants, and composite (mixed
  tenant/cell) setups. See [Silo adapters](silo-adapters.md).
- `keks/`: decides KEK identity and lifecycle, independent of the KMS wire
  protocol.
  - `keks/strategies`: maps a silo reference (key set and uid) to a KEK resource
    name (shared, per-silo, cohort, composite, BYOK). A strategy is chosen per
    key store block, with one template per store. See
    [KEK strategies](kek-strategies.md).
  - `keks/provisioners`: optionally creates the KEK on the KMS on first use,
    for application-driven provisioning. Defaults to a no-op so KEKs can be
    provisioned out-of-band (Terraform, KMS console). See
    [KEK provisioning](kek-provisioning.md).
- `credentials/`: authenticates with external providers (GCP, AWS, Azure,
  Vault, IBM, OCI, Infisical). An `oidc_sources` sub-layer produces OIDC JWTs
  from a pluggable set of token sources (Fly.io, file-based for Kubernetes /
  IRSA / Azure Workload Identity / Nomad, GCP metadata, Vercel, SPIFFE); any
  source can be paired with any provider that exposes an OIDC-based auth
  method (AWS STS `AssumeRoleWithWebIdentity`, GCP Workload Identity
  Federation, Azure AD federated credentials, Vault JWT auth, Infisical OIDC
  auth). See [OIDC federation](how-oidc-works.md).
- `key_stores/`: encrypts and decrypts key material. A key store is one of two
  types: `kms`, a remote service (the cloud majors GCP, AWS and Azure,
  HashiCorp Vault, IBM Key Protect / HPCS, OCI Vault, Infisical, Fly.io KMS),
  or `env`, key material your settings supply to the process, wrapped locally
  by `environment.py`. See [KMS adapters](kms-adapters.md).
- `crypto_backends/`: the local data-plane crypto engine. It generates the
  DEK and performs the actual field (AEAD) and file (streaming AEAD)
  encryption and decryption, independent of the KMS that wraps the DEK.
  Selected via `CRYPTO_BACKEND`; defaults to pyca-cryptography (its
  `cryptography` dependency is core), with Google Tink available via the
  `[tink]` extra. See [Crypto backends](crypto-backends.md).

## Layer flow

On encrypt: `silo` → resolve the field's key set to a
named store (`KEY_SETS`) → `kek/strategies` (resolve the KEK id) →
`crypto_backends` (generate the DEK) → `credentials` → `key_stores` (wrap the DEK).
On first use, `kek/provisioners` may run ahead of the KMS call to create the
KEK. The DEK then encrypts the field or file value via `crypto_backends`.

On decrypt: `silo` → load the stored `DataEncryptionKey` row for that UID, key set and
purpose → `credentials` → `key_stores` (unwrap the DEK using the KEK resource name
recorded on the row) → `crypto_backends` (load the primitive from the
unwrapped DEK and decrypt). `kek/strategies` is not consulted: the stored row
already carries the KEK id, so strategy changes cannot strand
previously-written ciphertext. Unwrapped DEKs are cached in-process for
`DEK_CACHE_TTL` seconds to avoid a KMS round-trip per read.

## Framework integrations

Optional integrations live outside `adapters/` under `contrib/`, so the core
stays independent of any one framework. A module that imports an external
framework sits behind an extra, such as `[drf]` for the Django REST Framework
error handler, serializer mixin, and download negotiation class (see
[Working with Django REST Framework](working-with-django-rest-framework.md)).
One that imports none needs no extra:

- `contrib/allauth.py`: an adapter mixin for the MFA secrets django-allauth routes
  through its adapter. See [Working with django-allauth](working-with-django-allauth.md).
- `contrib/simpleteams`: an optional app with a team model, its silo adapter,
  middleware and admin, for projects with no team model of their own. It creates
  tables only when it is in `INSTALLED_APPS`. See
  [Simple teams](simple-teams.md).
