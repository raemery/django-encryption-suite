# Compliance evidence

django-encryption-suite keeps records about its keys and algorithms, and many
security and privacy frameworks ask for exactly that kind of evidence. This page
describes those records once, then shows for each framework which of its
requirements the records bear on. It states facts about the package. It does not
claim that a deployment using the package complies with anything: your assessor
or counsel decides which requirements apply to you and whether a record meets
them.

## General

### Records

The package keeps one record itself and produces three more for you to keep.

- **The key lifecycle record.** The package writes one
  [key lifecycle event](key-lifecycle-events.md) for every act on a key, in the
  same database transaction as the act. Events are never updated or deleted.
  Each data key event records what protected the key after the act: the key
  encryption key, its key store and version, the crypto backend and the algorithm.
  [`USER_IDENTITY`](configuration.md#user_identity) decides whether an event also
  records the user, the operating-system account and the IP address behind it.
- **The cryptographic inventory.**
  [`crypto_inventory`](management-commands.md#crypto_inventory) reports every key store,
  the key encryption keys on it, the data encryption keys per purpose, backend
  and algorithm, and what a key generated now would get.
- **Command reports.** The inventory, reconcile and re-encryption commands write
  a JSON document per run and exit non-zero when work failed. See
  [Command output](scheduled-tasks.md#command-output).
- **Log lines.** Every management command logs a WARNING line when it starts, and
  the re-encryption commands log their counts when they finish. See
  [logging](logging.md).

The package stores only the first. Your scheduler, log collector or compliance
tool keeps the reports and log lines, compares them over time, and holds them for
as long as each framework below requires. Most frameworks reward evidence that is
dated and repeated, so schedule the inventory and reconcile commands rather than
running them only before an assessment.

### Omissions

- **Key material.** No record holds a key, wrapped or plain.
- **Each encrypt and decrypt.** Encrypting or decrypting a value writes no
  event. The data key fixes the algorithm that protects a value, and the record
  already holds the data key's history. To log reads, turn on
  [`LOG_DECRYPTS`](configuration.md#log_decrypts).
- **The KMS's own state.** The inventory reports what this deployment knows.
  [Reconcile](admin-panel.md#reconcile-keys-page) compares that with what the KMS
  holds.

### Exposure

The protection columns on each event name a KMS, a key encryption key, its
version, a backend and an algorithm. The data key row already holds the current
value of each, and the key encryption key rows already name every key. Someone
who can read the database therefore learns only the history from these columns.
None of it helps them decrypt anything: the algorithms are public by design, and
the keys stay on the KMS.

The identity columns are different, because they hold personal data. A privacy
framework's limits on keeping personal data apply to them, so set
`USER_IDENTITY` to record only what you need, and encrypt what you record.

### Privacy laws that ask for appropriate measures

Most privacy laws require "appropriate" or "reasonable" security measures and
name encryption as an example, but ask for no specific record. For these laws,
the package's records show what protects the data and when that changed, which
is the evidence an investigation after an incident usually asks for. Several also
relax breach notification for data that was encrypted when it was taken.

| Law | Where | What it asks for |
|---|---|---|
| CCPA / CPRA | California | Reasonable security. Regulations in force from January 1, 2026 add annual cybersecurity audits, phased in from 2028. |
| State breach-notification laws | Most US states | Notice after a breach of personal data. Most exempt data that was encrypted and whose key was not taken. |
| PIPEDA | Canada (federal) | Safeguards suited to the sensitivity of the data (Principle 4.7). |
| Law 25 | Quebec | Security measures, and privacy impact assessments. |
| PHIPA | Ontario | Safeguards for personal health information. |
| LFPDPPP | Mexico | Security measures. The current law has been in force since March 21, 2025. |
| Law 21.719 | Chile | Security measures, with a data protection agency. In force from December 1, 2026. |
| Law 25.326 | Argentina | Security measures for personal data. |
| Law 1581 of 2012 | Colombia | Security measures for personal data. |
| Law 29733 | Peru | Security measures for personal data. |
| Law 18.331 | Uruguay | Security measures for personal data. |

The frameworks below ask for more specific evidence, so each has a section of its
own.

## PCI DSS v4.0.1

### Scope

PCI DSS applies to anyone who stores, processes or transmits payment card data.
Its key-management requirements apply wherever the package encrypts account
data.

### Requirements

| Requirement | What it asks for | What the package provides |
|---|---|---|
| 3.5.1 | Stored account numbers unreadable, for example by strong cryptography | Encrypted fields and files, each silo under its own data key |
| 3.6.1 | Keys protected; a key-encrypting key at least as strong as the key it protects, stored apart from it | Envelope encryption: data keys are stored only wrapped, and the key encryption key stays on the KMS |
| 3.6.1.1 (service providers) | A documented cryptographic architecture: algorithms, keys and key strength | `crypto_inventory` |
| 3.7.x | Key generation, change at the end of a cryptoperiod, retirement and destruction | The key lifecycle record, `DEK_ROTATION_PERIOD_DAYS`, `reencrypt_keys`, `reencrypt_data` and scheduled key deletion |
| 10.2 | Audit logs of who did what, and when | The identity on each event, and the WARNING line each command logs |
| 12.3.3 | An inventory of cipher suites and protocols in use, reviewed at least every 12 months | `crypto_inventory --format json`, kept with each review. Its "configured for new data encryption keys" section shows keys still on an older algorithm. |

### Retention

PCI DSS requires audit log history for at least 12 months, with the latest
three months immediately available (Requirement 10.5.1). The key lifecycle record
is never deleted, so it outlasts that. Keep the command reports and log lines for
at least as long.

### Out of scope

The package does not cover encryption in transit (Requirement 4), key custody at
the KMS, or the documented procedures and the annual review themselves. It
supplies the evidence a review reads, not the review.

## HIPAA Security Rule

### Scope

The Security Rule applies to covered entities and their business associates that
hold electronic protected health information (ePHI).

### Requirements

| Requirement | What it asks for | What the package provides |
|---|---|---|
| §164.312(a)(2)(iv) | Encryption and decryption of ePHI (an addressable specification) | Encrypted fields and files |
| §164.312(b) | Mechanisms that record and examine activity in systems holding ePHI | The key lifecycle record; `LOG_DECRYPTS` for reads |
| §164.308(a)(1) | Risk analysis and risk management | `crypto_inventory` and reconcile reports, as inputs to the analysis |
| Breach Notification Rule (§164.402) | Notice after a breach of *unsecured* ePHI | Data encrypted to HHS guidance is not "unsecured" while its key is safe. The key lifecycle record shows which key protected the data, and when. |

### Retention

HIPAA requires keeping required documentation for six years from its creation or
from when it was last in effect, whichever is later (§164.316(b)(2)(i)). Keep the
inventory and reconcile reports for six years.

### Out of scope

The package does not cover transmission security (§164.312(e)), access control
to the application, or the written policies and risk analysis themselves.

## GLBA Safeguards Rule

### Scope

The FTC's Safeguards Rule (16 CFR Part 314) applies to financial institutions
under the FTC's jurisdiction that hold customer information.

### Requirements

| Requirement | What it asks for | What the package provides |
|---|---|---|
| §314.4(c)(2) | Identify and manage the data, systems and devices that hold customer information | `crypto_inventory` for the cryptographic part of that inventory |
| §314.4(c)(3) | Encryption of customer information at rest and in transit | Encrypted fields and files (at rest) |
| §314.4(c)(8) | Monitoring and logging of authorized users' activity | The key lifecycle record and the command log lines |
| §314.4(i) | A written report to the board at least once a year | The year's inventory and reconcile reports, as inputs |

### Retention

The rule sets no retention period for these records. Follow your own records
policy.

### Out of scope

The package does not cover encryption in transit, user access controls, or the
written information security program.

## NYDFS Cybersecurity Regulation (23 NYCRR 500)

### Scope

Part 500 applies to entities licensed or regulated by the New York State
Department of Financial Services.

### Requirements

| Requirement | What it asks for | What the package provides |
|---|---|---|
| §500.15 | Encryption of nonpublic information at rest and in transit, or compensating controls the CISO approves and reviews every year | Encrypted fields and files (at rest) |
| §500.13 | A complete, current asset inventory | `crypto_inventory` for the keys and algorithms |
| §500.6 | Audit trails | The key lifecycle record and the command log lines |
| §500.17(b) | An annual certification of compliance | The year's inventory and reconcile reports, as supporting documents |

### Retention

Part 500 requires keeping the records that support each annual certification
for five years. Keep the year's inventory and reconcile reports with them.

### Out of scope

The package does not cover encryption in transit, multi-factor authentication,
or the cybersecurity program and its policies.

## GDPR

### Scope

The GDPR applies to the processing of personal data of people in the European
Union, and to organizations outside the EU that offer them goods or services or
monitor them.

### Requirements

| Requirement | What it asks for | What the package provides |
|---|---|---|
| Art. 32(1)(a) | Pseudonymization and encryption of personal data | Encrypted fields and files |
| Art. 32(1)(d) | Regular testing of the security measures | Scheduled reconcile and inventory reports; the admin test console |
| Art. 5(2) | Accountability: the ability to demonstrate compliance | The key lifecycle record and the inventory |
| Art. 17 | Erasure | Deleting a silo's keys makes its encrypted data unreadable; the record shows when |
| Art. 34(3)(a) | No notice to data subjects after a breach of data that was unintelligible, for example encrypted | The key lifecycle record shows the data was encrypted, and under which key |

### Retention

The GDPR sets no retention period for security records. Its storage limitation
principle (Art. 5(1)(e)) applies to the personal data inside them, which in this
package means the identity columns. Record only the identity you need.

### Out of scope

The package does not cover the records of processing (Art. 30), the lawful basis
for processing, or data subject requests other than erasure by key deletion.

## LGPD

### Scope

Brazil's LGPD (Law 13.709) applies to the processing of personal data in Brazil,
or of people in Brazil.

### Requirements

| Requirement | What it asks for | What the package provides |
|---|---|---|
| Art. 46 | Technical and administrative security measures | Encrypted fields and files |
| Art. 6(X) | Accountability: the ability to demonstrate effective measures | The key lifecycle record and the inventory |
| Art. 48 | Notice to the ANPD and data subjects of a security incident that may cause relevant harm | The key lifecycle record shows which data was encrypted, and under which key |
| Art. 16 | Deletion when processing ends | Deleting a silo's keys makes its encrypted data unreadable |

### Retention

The LGPD sets no retention period for security records. Like the GDPR, it limits
how long you keep the personal data inside them, which in this package means the
identity columns.

### Out of scope

The package does not cover the records of processing (Art. 37), the legal basis
for processing, or the data protection officer's duties.
