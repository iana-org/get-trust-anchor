# DNSSEC Trust Anchor Fetcher

[![Build Status](https://api.travis-ci.org/kirei/get_trust_anchor.png)](https://travis-ci.org/kirei/get_trust_anchor)

This tool writes out a copy of the current DNSSEC trust anchor. It is compatible with both Python 2.7 and Python 3.x, and has no external dependencies.

The DNSSEC trust anchor will be fetch from [IANA](https://www.iana.org/dnssec), and the root KSK (Key Signing Key) will be fetched using [Google Public DNS](https://developers.google.com/speed/public-dns/) over HTTPS or by downloading the [root zone file](https://www.internic.net/domain/root.zone).


## Usage

    python get_trust_anchor.py

## Root zone Trust Anchors

- https://www.iana.org/dnssec
- https://data.iana.org/root-anchors/root-anchors.xml
