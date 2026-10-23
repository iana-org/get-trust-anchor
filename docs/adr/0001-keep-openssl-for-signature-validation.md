# ADR 0001: Keep openssl for signature validation

- **Status:** Proposed
- **Date:** 2026-10-22

## Context

get-trust-anchor validates the S/MIME signature on IANA's `root-anchors.xml`
with the openssl command line tool:

```
openssl smime -verify -CAfile <CA file> -inform der -in <p7s> -content <xml>
```

Only the built-in ICANN CA certificates, or a `--root-ca` file, should be able
to anchor the signature. But
`openssl smime -verify` also uses openssl's default trust locations (the
default CA directory and, on OpenSSL 3, the default CA store), and how to turn
those off differs between OpenSSL and LibreSSL versions.

## Observations

A `root-anchors.xml` signed under a test CA added to
the system trust store, was accepted when run using the built-in ICANN CA certificates:

| Runtime | Test CA added with | Options that rejected it |
|---|---|---|
| OpenSSL 4.0.3, Fedora 45 | hashed into `/etc/pki/tls/certs` | `-no-CApath -no-CAstore` |
| OpenSSL 3.0.13, Ubuntu 24.04 | `update-ca-certificates` | `-no-CApath -no-CAstore` |
| OpenSSL 1.1.1f, Ubuntu 20.04 | `update-ca-certificates` | `-no-CApath` |
| OpenSSL 1.1.1k, Rocky Linux 8 | hashed into `/etc/pki/tls/certs` | `-no-CApath` |
| LibreSSL 4.3.1, Alpine 3.24 | hashed into `/etc/ssl/certs` | `-CApath <empty dir>` |

With those options, IANA's published file still validated (checked on
OpenSSL 4.0.3, 3.0.13, 1.1.1k and LibreSSL 4.3.1). The same failure was
reproduced in CI on Ubuntu, Rocky Linux 8 and Alpine, and locally on Fedora 45.

`openssl smime -verify` given an option it does not recognise:

| Runtime | Exit code | Verified |
|---|---|---|
| OpenSSL 4.0.3 | 0 | no |
| OpenSSL 3.0.13 | 0 | no |
| OpenSSL 1.1.1k | 0 (also for `-no-CAstore`) | no |
| LibreSSL 4.3.1 | 0 (also for `-attime`) | no |
| LibreSSL 3.3.6, macOS | 1 | no |

A successful verification exited 0 and printed `Verification successful` on
all five; that text is not a documented interface. The LibreSSL behaviour
contradicts its own documentation (exit 1 for option errors) and has been
reported upstream.

## Constraints

- Runtime: Python 3.10 or later and the openssl command line tool.
- openssl versions on current systems and those still in LTS support:
  - OpenSSL 4.x - Fedora 45.
  - OpenSSL 3.x - current Linux distributions.
  - OpenSSL 1.1.1 - RHEL 8 supported until 2029-05-31.
  - LibreSSL - OpenBSD and DragonFly BSD.

## Decision

Keep openssl (and LibreSSL) as the signature verifier, and add the options that
limit trust to `-CAfile`, chosen from `openssl version`:

| `openssl version` | Options |
|---|---|
| OpenSSL 3 or later | `-no-CApath -no-CAstore` |
| OpenSSL 1.1 | `-no-CApath` |
| LibreSSL | `-CApath <empty directory>` |
| anything else | refuse to validate |

`--system-trust-options="..."` replaces these options with the operator's
own, unrestricted, and logs a warning naming them. The openssl version is
logged on every run.

Because the exit code alone does not show that verification happened,
validation succeeds only if openssl also reports `Verification successful` on
stderr. Otherwise the tool fails and says openssl did not report successful verification.

## Alternatives considered

- **`cryptography` package.** No high-level PKCS#7/S/MIME verification; an
  earlier attempt built from primitives missed checks across the full certificate chain. Avoid writing our own PKCS#7 verification routines.
- **Python `ssl` module.** Cannot verify PKCS#7.
- **`openssl cms -verify`.** Same default-trust behaviour.
- **Detect options from `openssl smime -help`.** Shows which options exist,
  not which combination excludes all default trust locations. Choosing
  correctly still needs per-implementation knowledge, and an unknown trust
  location would go unnoticed. Help output is not an interface.
- **`SSL_CERT_DIR` / `SSL_CERT_FILE`.** LibreSSL ignored `SSL_CERT_DIR`.
- **Operator-selected profiles.** A stale profile could silently drop the
  protection.

## Consequences

- No new runtime dependency.
- The version table needs maintaining as openssl changes.
- An unrecognised openssl stops validation until the table is updated or the
  operator uses `--system-trust-options`.
- An override can weaken validation; this is the operator's responsibility
  and is logged. An option openssl does not recognise fails rather than
  passing unverified.
- Validation depends on openssl's `Verification successful` text, which is
  not a documented interface. If a future openssl changes it, validation fails
  closed until the tool is updated.
  