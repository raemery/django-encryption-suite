# OIDC federation

This document explains the `oidc` credential strategy at a conceptual level:
what a federated OIDC exchange actually is, the claims that drive it, and the
kinds of problems you hit when wiring one up — with general solutions for each.

It is provider-neutral on purpose. For the per-provider option tables and the
list of token sources, see [KMS adapters](kms-adapters.md#oidc-token-sources).
For the end-to-end setup on a specific provider, see that provider's
`getting-started-*.md`. If you are new to envelope encryption, read
[concepts.md](concepts.md) first; for what the KMS does once authenticated, see
[how-kms-works.md](how-kms-works.md).

---

## Benefits of federated OIDC

The other credential strategies hand the KMS a long-lived secret — a static
access key, a client secret, a service token. Someone has to store that secret,
scope it, and rotate it, and it is a standing target if it leaks.

OIDC federation removes the stored secret. The platform the workload runs on
(Fly.io, Kubernetes, GCP, Vercel, a SPIFFE mesh) issues the workload a
**short-lived, signed assertion** about its own identity. The KMS provider is
configured ahead of time to **trust that issuer** for a specific identity. At
call time the workload presents the assertion, the provider verifies the
signature and the claims, and hands back temporary provider credentials. Nothing
secret is stored in the application; the assertion expires on its own.

The cost is setup complexity: instead of pasting a key, you establish a trust
relationship between two systems, and trust relationships fail in quiet,
asymmetric ways. The rest of this page is about getting that relationship right
and recognizing it when it is wrong.

---

## The two-axis model

encryption_suite splits `oidc` into two independent pieces so any platform can reach
any KMS without a strategy per combination:

1. **A token source** produces the signed OIDC JWT for a requested audience.
   Chosen with the required `OIDC_SOURCE` option (`fly`, `file`, `gcp_metadata`,
   `vercel`, `spiffe`).
2. **A provider exchange** consumes that JWT and returns provider credentials —
   AWS STS `AssumeRoleWithWebIdentity`, GCP Workload Identity Federation, Azure
   AD federated credentials, Vault's JWT auth method, Infisical's OIDC auth.

The full source list, their options, and the per-provider exchange settings live
in [KMS adapters → OIDC token sources](kms-adapters.md#oidc-token-sources). This
page is about what flows between the two axes and why an exchange gets refused.

---

## Anatomy of the assertion

The JWT the workload presents is three base64url segments joined by dots:
`header.payload.signature`. The payload is a JSON object of **claims**. Three
claims decide whether the exchange succeeds:

- **`iss` (issuer)** — who signed the assertion, as a URL. The provider fetches
  this issuer's public keys to verify the signature, usually via OIDC discovery
  at `<iss>/.well-known/openid-configuration` and the JWKS endpoint that document
  advertises. The issuer URL is the public, verifiable side of the relationship —
  it is what you register on the provider.
- **`aud` (audience)** — who the assertion is *for*. The workload requests a
  specific audience when it asks for the token; the provider rejects the
  assertion unless that audience matches what it was told to expect. The
  audience is not a secret; it is a label that stops a token minted for one
  consumer from being replayed against another.
- **`sub` (subject)** — *which* workload under that issuer. This is the
  identity the provider's trust binding pins to. Its shape is issuer-defined and
  is often **composite** — a platform typically encodes account, app, and
  instance into one string.

On the provider side, the condition keys that match these claims are usually
namespaced by the issuer host. A trust rule does not say "`sub` equals X"; it
says "for the issuer `oidc.example.com/acme`, the claim `sub` equals X" — the
issuer host is a prefix on the claim name. Getting that prefix wrong is
indistinguishable, to a quick read, from getting the value wrong.

---

## Token issuance

The workload never stores a token. The platform supplies a fresh one, and the
sources differ in who picks the audience:

- **The workload requests it.** The `fly`, `gcp_metadata` and `spiffe` sources
  ask the platform for a token with the audience the provider expects, on
  every exchange.
- **The platform fixes it.** The `file` and `vercel` sources read a token
  that already carries its audience, set in the platform's own configuration.
  The package ignores its audience setting for these sources, so the platform
  configuration must name the audience the provider expects.

Sources also differ in the shape of `sub`. Some issuers give every instance of
a workload the same subject. Others put the instance in it, which causes most
subject-matching problems (see below). On Fly.io, for example, `sub` is
`<org>:<app>:<machine-name>`, and the machine name changes when the app scales.
[Fly.io as an OIDC token source](getting-started-fly.md#flyio-as-an-oidc-token-source)
lists every Fly value used in the provider guides.

### Inspecting claims on the workload

When an exchange is refused, start by reading the claims the workload *actually*
presents, not the ones you assume. Fetch a token the same way the source does
and decode the middle (payload) segment as base64url to see `iss`, `sub`, and
`aud`.

> **The token is a live credential.** Decode and read the claims only. Never
> paste the raw token into a chat, an issue, or a shared log — anyone holding it
> can impersonate the workload until it expires. This is the same reason the
> transport must be TLS (below).

---

## Provider trust setup

Regardless of provider, configuring the KMS side is the same three moves:

1. **Register the issuer.** Point the provider at the issuer URL (or its
   discovery/JWKS endpoint) so it can verify signatures. Some providers want the
   bare issuer URL and append `/.well-known/...` themselves; others want the full
   discovery URL. Supplying the wrong form is a common first-setup failure.

   The issuer side is public, and nothing on it is secret. Open the discovery
   document in a browser or with `curl` to see exactly what the provider reads:

   ```bash
   curl <issuer-url>/.well-known/openid-configuration
   ```

   The document names the issuer, the claims it emits, and the `jwks_uri` that
   holds its public signing keys. The JWKS holds only public keys; the private
   signing key never leaves the issuer, and the workload's token is the part
   that stays secret. Let the provider discover the `jwks_uri` from the
   document rather than hard-coding it, because each issuer chooses its own
   path. Fly.io's, for example, is `/.well-known/jwks`, and `jwks.json`
   returns 404.
2. **Fix the audience.** Tell the provider which `aud` to require, and make the
   workload present exactly that audience. When the source requests the
   audience, the package option sets it; when the platform fixes it, the
   platform configuration does. The two values must match
   character-for-character; there is no negotiation at runtime.
3. **Bind the subject.** Restrict which `sub` values the trust accepts. The
   binding stops *any* workload under the issuer from assuming the identity.
   Providers differ in how tightly you can bind and whether they accept
   wildcards, which is the heart of the subject-matching problems below.

The concrete syntax (trust policy, workload-identity provider, federated
credential, JWT role, OIDC auth method) is in each provider's
`getting-started-*.md`. The failure *modes* are shared, so they are collected
here once.

---

## Common problems and solutions

These are grouped by the **kind** of failure, because the same underlying
problem surfaces with different provider-specific error text. Identify the class
first; the fix follows from the class.

### 1. The token is valid but authorization is denied

The provider verified the signature and accepted the token, but the trust
binding does not match the claims presented, so the exchange is refused. The
tell is an *authorization* error (e.g. "access denied", "not authorized",
"subject not allowed") rather than a *token-invalid* error — the request got
past signature and audience validation and was rejected by the trust rule.

Typical causes:

- An **unsubstituted placeholder** left in the trust config — a template
  `<account-id>`, `<org>`, or `<project>` never replaced with the real value, so
  the rule trusts a resource that does not exist. This looks correct on a skim
  and fails total.
- A **claim/condition mismatch**: the trust requires an `iss`, `aud`, or `sub`
  that differs from what the workload actually presents — including the
  issuer-host prefix on the condition key being wrong.

General solution: decode the live token claims on the workload (above), then
compare each of `iss`, `aud`, `sub` against the provider-side binding
line by line, including any placeholders and the claim-name prefixes. Read the
provider's audit record of the *failed* exchange to see the identity and
resource it actually evaluated, and reconcile that against the policy. The fix
is always to make the binding match the real claims, not to loosen it blindly.

### 2. Subject matching breaks across rotating or multiple instances

The workload's `sub` carries an instance component (a machine name, for example)
that is not stable, and the app runs more than one instance. Issuers that give
every instance the same `sub` do not have this problem. A trust bound to one
exact subject authenticates the instance you tested and then refuses the next
one — which appears the moment another instance serves a request, including a
previously stopped instance that autostarts. This reads as intermittent: it
"works," then 403s, then works.

General solution: bind the subject to a **glob scoped to the app**
(e.g. `<org>:<app>:*`) where the provider supports wildcard subject matching, so
trust survives instance rotation while still pinning to this one app. Where the
provider **refuses wildcard subjects** for your issuer, you must either
enumerate one binding per instance subject (and keep it in sync as instances
change, against whatever per-identity cap the provider imposes) or choose a
different auth method for that provider. Avoid an empty/unbound subject: it
authenticates but trusts *every* workload under the issuer, which is far wider
than intended. When diagnosing, first confirm how many instances are actually
serving — a second instance presenting a different `sub` is a frequent cause of
"my glob doesn't work" that is really "I was testing one instance and traffic
hit another."

### 3. The token is rejected before authorization

Here the provider never gets to the trust rule — it cannot validate the token
itself. The error names the *token* or *identity* as invalid rather than denying
access.

Typical causes: the issuer's discovery/JWKS endpoint is unreachable or the
discovery URL was registered in the wrong form; the requested audience is not
registered on the provider; clock skew between issuer and provider puts the
token outside its validity window.

General solution: confirm the issuer's discovery and JWKS endpoints are
reachable from the provider and that you registered the URL in the form that
provider expects (bare issuer vs. full discovery URL). Confirm the audience the
workload requests is exactly the one registered. Because this class is about the
token's own validity, decoding the claims tells you less than checking the
issuer-registration and audience-registration on the provider.

### 4. The new configuration never actually shipped

The exchange "still uses the old auth" because the code path that reads the new
OIDC settings was never deployed. On platforms where setting a secret produces a
config-only release that **reuses the existing image**, a secret change restarts
the workload but does not rebuild — so a settings branch that reads a new
variable has no effect until a real rebuild ships it. The result is a false pass
or a confusing failure against config you believe is live.

General solution: when a credential change also touches code, pair the secret
change with a rebuild/redeploy, and verify a *new* build actually shipped (not a
reused image). Confirm from the workload's logs that the new auth path is in use
and that any old secret has been removed — an exchange that silently falls back
to a static key still present in the environment is not a real test of OIDC.

### 5. The real reason is hidden in a log you are not reading

Providers routinely **mask** the cause of a federated-auth failure in the
client-facing error (a generic "an unknown error occurred" or a flat "denied")
to avoid leaking trust-policy detail to an unauthenticated caller. The actionable
detail is in the provider's own audit log — and that log may be in a
**different region or scope** than you are looking at, because the federation
exchange endpoint is often global even when the keys it guards are regional.

General solution: know where your provider records the federation exchange and
read the failed event there; it shows the identity and resource actually
evaluated, which is what pins the mismatch. Use the *error class* to localize the
phase — an authorization denial points at the trust binding (problem 1/2), a
token-invalid error points at validation (problem 3). Keep in mind that
identities and issuer registrations are frequently global resources while the
encryption keys are regional, so "it's not there" may just mean you are viewing
the wrong region's log.

### 6. The token leaks in transit or at rest

The assertion is a bearer credential for its lifetime. Sent over plaintext
`http://` to a non-local host, or read from a file an unprivileged process can
write or swap, it can be captured or forged, letting an attacker impersonate the
workload to your KMS.

General solution: use `https://` for any non-local exchange endpoint — the
library warns at construction when it sees a plaintext URL to a remote host;
treat that as a defect, not noise. For file-based sources, ensure the token file
and every parent directory are writable only by the orchestrator. And, as above,
never share or store the raw token; read only its claims. The
[security considerations for OIDC sources](kms-adapters.md#security-considerations-for-oidc-sources)
section covers the per-source specifics.

---

## Related reading

- [KMS adapters → OIDC token sources](kms-adapters.md#oidc-token-sources) — the
  source list, per-provider exchange options, and security considerations.
- [KMS internals](how-kms-works.md) — what the KMS does once the
  workload is authenticated.
- [Security model](security.md) — the package's overall threat model.
- The per-provider `getting-started-*.md` guides — concrete trust setup for AWS,
  GCP, Azure, Vault, and Infisical.
