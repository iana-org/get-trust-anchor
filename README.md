# DNSSEC Trust Anchor Tool

This tool fetches the current DNSSEC root trust anchor from
[IANA](https://www.iana.org/dnssec), cryptographically validates it,
and writes out the root KSK (Key Signing Key) as DNSKEY and DS
records.

It requires [Python](https://www.python.org/) 3.10+ and the
[OpenSSL](https://www.openssl.org/) command line tool. There are no
other dependencies.

## How it works

1. Fetches the trust anchor XML from IANA over HTTPS
2. Fetches the corresponding S/MIME signature from IANA
3. Validates the signature using a built-in ICANN Root CA certificate
4. Extracts the trust anchor key digests from the XML
5. Checks the validity period for each digest
6. Fetches the current root KSK via [Google Public DNS](https://developers.google.com/speed/public-dns/)
   over HTTPS (falling back to the [root zone file](https://www.internic.net/domain/root.zone))
7. Matches the KSKs against the trust anchors and writes them out

The signature validation uses a CA certificate embedded in the tool
itself, so the trust anchors are cryptographically verified regardless
of whether HTTPS certificate checking succeeds.

## Installation

Install from the repository:

    pip install .

This provides a `get-trust-anchor` command.

## Usage

Run the installed command:

    get-trust-anchor

Or invoke as a Python module:

    python -m get_trust_anchor

### Options

| Option | Description |
|---|---|
| `--local FILE` | Use a local trust anchor XML file instead of fetching from IANA |
| `--local-sig FILE` | Use a local signature file instead of fetching from IANA |
| `--root-ca FILE` | Use a custom root CA certificate instead of the built-in one |
| `--no-validation` | Skip signature validation |
| `--ksks-from-trust-anchor` | Extract KSKs directly from the trust anchor XML instead of fetching from DNS |
| `--keep` | Keep temporary files (XML and signature) after running |
| `--print-dnskey` | Print DNSKEY records to stdout instead of writing files |
| `--print-ds` | Print DS records to stdout instead of writing files |

### Output

By default, the tool writes two files to the current directory:

- `ksk-as-dnskey.txt` -- root KSKs as DNSKEY records
- `ksk-as-ds.txt` -- root KSKs as DS records

Use `--print-dnskey` or `--print-ds` to print records to stdout
instead, suitable for piping:

    get-trust-anchor --print-ds | grep "^. IN DS"

## Development

Install with development dependencies:

    pip install -e ".[dev]"

Run the tests:

    pytest

Check formatting, lint, and types:

    ruff format --check .
    ruff check .
    ty check

## License

BSD 2-Clause. See [LICENSE](LICENSE) for details.
