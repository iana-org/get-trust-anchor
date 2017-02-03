# DNSSEC Trust Anchor Fetcher

This tool writes out a copy of the current DNSSEC trust anchor. It is compatible with both Python 2.7 and Python 3.x, and has no dependencies except [Python](https://www.python.org/) and the [OpenSSL](https://www.openssl.org/) command line tool.

The DNSSEC trust anchor will be fetch from [IANA](https://www.iana.org/dnssec), and the root KSK (Key Signing Key) will be fetched using [Google Public DNS](https://developers.google.com/speed/public-dns/) over HTTPS or by downloading the [root zone file](https://www.internic.net/domain/root.zone).


## Usage

    python get_trust_anchor.py

## Root zone Trust Anchors

- https://www.iana.org/dnssec
- https://data.iana.org/root-anchors/root-anchors.xml
