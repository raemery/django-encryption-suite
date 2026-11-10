# Moving to production

Work station development and tests usually run silo keys on an
env key store (`"KEY_SETS": {"default": {"silo": "...", "key_store": "login"}}`). Before you serve real data you must switch to
a real KMS, decide how KEKs relate
to silos, wire the silo adapter against the model that
actually represents your tenants, and — if any model declares a system
encrypted field — set the keys those columns are encrypted under.

This page is the checklist and the set of pointers. The per-provider
pages carry the click-by-click detail.

## 1. Choose a real KMS adapter

Pick the provider your infrastructure already uses. The data path is
identical across adapters — only the credentials and resource names
change.

- [AWS KMS](getting-started-aws.md)
- [GCP Cloud KMS](getting-started-gcp.md)
- [Azure Key Vault](getting-started-azure.md)
- [HashiCorp Vault](getting-started-hashicorp.md)
- [IBM Key Protect / HPCS](getting-started-ibm.md)
- [OCI Vault](getting-started-oci.md)
- [Infisical KMS](getting-started-infisical.md)

Install the matching extra:

```bash
uv add 'django-encryption-suite[aws]'
uv add 'django-encryption-suite[gcp]'
uv add 'django-encryption-suite[azure]'
uv add 'django-encryption-suite[hashicorp]'
```

Configure the adapter as a [`KMS_KEY_STORES`](configuration.md#kms_key_stores)
block and give the `default` key set that block in
[`KEY_SETS`](configuration.md#key_sets), such as
`{"default": {"silo": "...", "key_store": "aws"}, "system": {"key_store": "login"}}`.
With a KMS store beside an env store, every key set needs a `key_store`. See the
[KMS adapters reference](kms-adapters.md) for the full option matrix.

If the deployment already holds data under the env key store, keep that working: run
`reencrypt_keys` after the switch, and it re-wraps every silo key under the new
block. See [Moving to another KMS](key-rotation.md#moving-to-another-kms).

Running production silo keys on an env store is possible: every silo then shares
one key encryption key held in your settings. That fits a deployment that only
uses the system-wide silo.

## 2. Choose a KEK strategy

The KEK strategy decides how KEK resource names are derived from
silo UIDs. Four common shapes; the first two are built in, and the other two
are custom strategies you write:

- **Shared** (built in: `SharedKekStrategy`). One KEK wraps every tenant's
  DEK. Cheapest and simplest; compromise of that KEK affects all tenants.
- **Per-silo** (built in: `PerSiloKekStrategy`). Each tenant gets its own
  KEK. Strongest isolation and per-tenant key custody; costs and quota scale
  with tenant count.
- **Cohort** (custom). Tenants are grouped into cohorts (e.g., by region or
  plan); each cohort shares a KEK.
- **Composite** (custom). Different strategies for different key sets
  in the same project.

Full trade-off analysis and BYOK patterns: [KEK strategies](kek-strategies.md).

## 3. Decide how KEKs get created

Choose one of two models:

- **Out-of-band.** An operator (or IaC) creates each KEK on the KMS.
  The application never calls `CreateKey`. Works with every adapter.
- **Application-driven (auto-provisioning).** The KEK provisioner
  creates the KEK on first use. Requires the app's credentials to
  hold `CreateKey` (or the provider's equivalent) on the KMS. Every
  provider has a shipped provisioner; the env key store needs none.

The [Reconcile Keys page](admin-panel.md#reconcile-keys-page) tells you
exactly which KEK names your configured strategy expects — copy
those into the KMS console for the flow outside this application.

Full guide: [KEK provisioning](kek-provisioning.md).

## 4. Wire the silo adapter against the real tenant model

The local-dev guide uses a minimal `GenericModelSiloAdapter`
subclass. In production, point it at the model that actually
represents your tenants, and make sure the middleware that sets the
current silo runs after whatever resolves the tenant from the
request.

For the two managed integrations no middleware is needed:

- **django-tenants.** Use `DjangoTenantsSiloAdapter`. It reads
  from `connection.tenant`, already set by the django-tenants
  middleware. See [django-tenants integration](django-tenants.md)
  for schema placement and composite adapter patterns.
- **SaaS Pegasus.** Use `PegasusTeamSiloAdapter`. It reads from
  Pegasus's own team context.

See [Silo adapters](silo-adapters.md) for writing custom
adapters and for the composite pattern when your project has more
than one kind of silo.

## 5. Turn on audit logging

Route the `encryption_suite.admin_test_console` logger to an append-only
sink (syslog, a WORM bucket, SIEM pipeline). The admin test console
and KMS probe emit one structured entry per call — preserving that
log is what lets an incident responder answer "did the admin UI
decrypt something it shouldn't have?".

Consider enabling `LOG_DECRYPTS` to log field-level decrypts.
Full detail: [Logging](logging.md).

## 6. Provision DEKs

For existing tenants, run the management command once:

```bash
python manage.py setup_encryption_keys
```

For new tenants created after launch, set `SILO_AUTO_KEY_CREATION`
in `ENCRYPTION` so DEKs are generated automatically on
silo creation. See the
[configuration reference](configuration.md) and
[management commands](management-commands.md).

## 7. Set `ENV_KEY_STORES` for the system key set

If any model declares a [`key_set="system"` column](system-wide-silos.md) — the
usual reason being the columns a sign-in reads, which must not depend on a team's
KMS — those columns use the system silo, whose keys an env store wraps
under `ENV_KEY_STORES`, and `KEY_SETS` gives the `system` key set that store.
Generate one per environment and read it from the same secret
manager as your KMS credentials:

```bash
openssl rand -base64 32
```

```python
ENCRYPTION = {
    "ENV_KEY_STORES": {"login": {"KEKS": {1: os.environ["ENC_SYSTEM_KEK"]}}},
    "KEY_SETS": {
        "default": {"silo": "...", "key_store": "aws"},
        "system": {"key_store": "login"},  # no silo: the system key set always uses the system silo
    },
}
```

A model declaring such a column while no store resolves for the `system` key set
fails `manage.py check` with `E038`, which is not downgradeable by
[`STARTUP_CHECK_WARN_ONLY`](configuration.md#startup_check_warn_only) — without
the key nobody can sign in to diagnose it. A project that declares no
`key_set="system"` column needs no `ENV_KEY_STORES`.

No KMS stands behind `ENV_KEY_STORES`, so nothing can restore it. Back it up wherever
you back up the KEK. Full detail: [System-wide silos —
Keys](system-wide-silos.md#keys); rotation is [Rotating a system
key](key-rotation.md#rotating-a-system-key).

## Deployment checklist

Before the first production deploy, confirm the following:

- [ ] `KEY_SETS` gives the `default` key set a real KMS block, not the
      development env store — or that is an accepted, deliberate posture. If the
      `system` key set is on a KMS store, `W058` is too.
- [ ] The block's `OPTIONS` carries real credentials (read from secret
      manager, not committed).
- [ ] Each block's `KEK_STRATEGY_ADAPTER` (`SharedKekStrategy`,
      `PerSiloKekStrategy`, or custom) is the deliberate choice for
      production, not one carried over from development.
- [ ] Key encryption keys exist on the KMS — cross-referenced against the
      Reconcile Keys page.
- [ ] Silo adapter points at the real tenant model. The
      test-console sentinel UID never collides with a real
      silo UID.
- [ ] Middleware that sets the silo runs after tenant
      resolution.
- [ ] `setup_encryption_keys` has run for all existing silos,
      or `SILO_AUTO_KEY_CREATION` is configured.
- [ ] `encryption_suite.admin_test_console` is routed to an append-only
      sink. `LOG_DECRYPTS` decision is made explicitly.
- [ ] If any model declares a `key_set="system"` column: `ENV_KEY_STORES` is set from a
      secret manager. The production value is not the dev one, and it is
      backed up — nothing can regenerate it.
- [ ] Secrets (`ENV_KEY_STORES`, cloud credentials) are **not** in version control.
- [ ] Staging has run the production adapter against a non-production
      KEK and the KMS probe returned success.
- [ ] Backup/recovery: you know how to restore the KMS KEK. Losing
      the KEK loses every DEK wrapped under it, which loses every
      encrypted value wrapped under those DEKs.
- [ ] Key rotation policy is documented and tested —
      [Key rotation](key-rotation.md).

## Features to disable

- A `KEY_SETS` entry that points the `default` key set at the development env
  store — replaced by the real block's name.
- The dev `ENV_KEY_STORES` — production gets its own, if it uses the env key store
  at all.
- Any `.env` that carries dev key material into production "for testing".

## Related

- [Security model](security.md) — threat model, what this package
  does and does not protect against
- [Operational concerns](operations.md) — caching, multi-process
  workers, ASGI, monitoring
- [Key rotation](key-rotation.md) — rotating KEKs, re-encrypting
