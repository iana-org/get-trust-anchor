#
# DNSSEC Trust Anchor Fetcher
# https://github.com/iana-org/get-trust-anchor
#
# Copyright (c) 2016, Paul Hoffman. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
DNSSEC Trust Anchor Fetcher

This tool writes out a copy of the current DNSSEC trust anchor.
    The primary design goal for this software is that it should be able to be run on any system
    that has just Python 3.10+ and the OpenSSL command line tool.

The steps it uses are:
    Step 1. Fetch the trust anchor file from IANA using HTTPS
    Step 2. Fetch the S/MIME signature for the trust anchor file from IANA using HTTPS
    Step 3. Validate the signature on the trust anchor file using the built-in ICANN CA certificates
    Step 4. Extract the trust anchor key digests from the trust anchor file
    Step 5. Check the validity period for each digest
    Step 6. Verify that the trust anchors match the KSK in the root zone file
    Step 7. Write out the trust anchors as a DNSKEY and DS records

Note that the validation is done against built-in ICANN CA certificates, not ones retrieved
through a URL. This means that even if HTTPS authentication checking isn't done, the resulting
trust anchors are still cryptographically validated.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime
import hashlib
import json
import os
import pprint
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version
from typing import Any, NoReturn
from urllib.request import urlopen

try:
    __version__ = version("get-trust-anchor")
except PackageNotFoundError:
    __version__ = "unknown"

# Type aliases
KskDict = dict[str, str | int]
TrustAnchorDict = dict[str, str]

# The built-in ICANN CA certificates, from https://data.iana.org/root-anchors/icannbundle.pem.
# A signature that chains to any of them is accepted.

# ICANN Root CA, valid 2009-12-23 to 2029-12-18, SHA-256 fingerprint
#   AE:E8:99:06:D7:CC:60:C5:E1:51:F3:BB:92:3A:BF:8A:1B:28:DC:85:5D:5E:21:27:CB:52:4E:AD:4A:AD:60:3D
ICANN_ROOT_CA = """-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBdMQ4wDAYDVQQKEwVJQ0FO
TjEmMCQGA1UECxMdSUNBTk4gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNV
BAMTDUlDQU5OIFJvb3QgQ0ExCzAJBgNVBAYTAlVTMB4XDTA5MTIyMzA0MTkxMloX
DTI5MTIxODA0MTkxMlowXTEOMAwGA1UEChMFSUNBTk4xJjAkBgNVBAsTHUlDQU5O
IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1JQ0FOTiBSb290IENB
MQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKDb
cLhPNNqc1NB+u+oVvOnJESofYS9qub0/PXagmgr37pNublVThIzyLPGCJ8gPms9S
G1TaKNIsMI7d+5IgMy3WyPEOECGIcfqEIktdR1YWfJufXcMReZwU4v/AdKzdOdfg
ONiwc6r70duEr1IiqPbVm5T05l1e6D+HkAvHGnf1LtOPGs4CHQdpIUcy2kauAEy2
paKcOcHASvbTHK7TbbvHGPB+7faAztABLoneErruEcumetcNfPMIjXKdv1V1E3C7
MSJKy+jAqqQJqjZoQGB0necZgUMiUv7JK1IPQRM2CXJllcyJrm9WFxY0c1KjBO29
iIKK69fcglKcBuFShUECAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAf4wHQYDVR0OBBYEFLpS6UmDJIZSL8eZzfyNa2kITcBQMA0GCSqGSIb3
DQEBCwUAA4IBAQAP8emCogqHny2UYFqywEuhLys7R9UKmYY4suzGO4nkbgfPFMfH
6M+Zj6owwxlwueZt1j/IaCayoKU3QsrYYoDRolpILh+FPwx7wseUEV8ZKpWsoDoD
2JFbLg2cfB8u/OlE4RYmcxxFSmXBg0yQ8/IoQt/bxOcEEhhiQ168H2yE5rxJMt9h
15nu5JBSewrCkYqYYmaxyOC3WrVGfHZxVI7MpIFcGdvSb2a1uyuua8l0BKgk3ujF
0/wsHNeP22qNyVO+XVBzrM8fk8BSUFuiT/6tZTYXRtEt5aKQZgXbKU5dUF3jT9qg
j/Br5BZw3X/zd325TvnswzMC1+ljLzHnQGGk
-----END CERTIFICATE-----"""

# ICANN Root CA v2, valid 2025-03-20 to 2045-03-20, SHA-256 fingerprint
#   D8:EE:E1:B7:42:08:B8:16:3E:1C:2B:99:0F:82:DD:9F:75:22:36:BA:13:0C:92:93:9E:77:28:EA:46:4E:BF:C3
ICANN_ROOT_CA_V2 = """-----BEGIN CERTIFICATE-----
MIIFsTCCA5mgAwIBAgIUQFsYkgroBoe69HKQPy8/DQuiLwgwDQYJKoZIhvcNAQEN
BQAwYDELMAkGA1UEBhMCVVMxDjAMBgNVBAoMBUlDQU5OMSYwJAYDVQQLDB1JQ0FO
TiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEZMBcGA1UEAwwQSUNBTk4gUm9vdCBD
QSB2MjAeFw0yNTAzMjAyMTA0MjZaFw00NTAzMjAyMTA0MjZaMGAxCzAJBgNVBAYT
AlVTMQ4wDAYDVQQKDAVJQ0FOTjEmMCQGA1UECwwdSUNBTk4gQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxGTAXBgNVBAMMEElDQU5OIFJvb3QgQ0EgdjIwggIiMA0GCSqG
SIb3DQEBAQUAA4ICDwAwggIKAoICAQCepDjrubjR7en/uZWo7MAnzFIIvUPYEc7b
+AlefdlEDQ1JEmpfrvt/4CX9lJ9ShIBR6zwrQeDvrj5XZ2kEjbJ8Nnc6sM/ojdyr
5jSLqcDPH9fJg7jCW02KF8CtqWsnqcW6jjTIZcCWkg9lEixdF8QAjIEgJtZte+Yh
XeyN0KD2EaO8U5Id0bLvMyphuO1OCGKzDtetcX8K7SvoshdJx3lPIlYzqXl0nVAY
iCeNdeDzTNjEOHYJOP6dYoZI8nKRJltMkZcCCjBE2vQuSMY2w4pOlWk1skHjMWXj
QsZzngXuNG56zialL0TPEDVWjWRjzOnruHUAs4KUY8Zs+Nt8JdSlXMi825PKoKpp
ESs7/ZG1mPjVOYp7Z7ntrRjJFgnUBjWzVPOx4yHiJj1ur+OpqP18oP5YfqY+tKmz
7vlfRGGOEd08a0XgZISDNKpMAovn5pRUHTWPCCjc28tns9ODPvr1cQi+QSwTv+v8
wnA5etGrsead88Rv/ieaq5ikMJTRDfW4d9SY2uPcMGvfU6VdQLRhQkzEVTQNAJ1R
i2lOoJbbjwnK+OU9OhST/OqdjJDJAhTAstdUnrr8WBU80xM75MIaaTjSBCvZ1wro
pAi2hYb0tedTH6WarSW3MH9HcEoGGzs2GD3hDB0a2eCp+TdAs8Up944SjY7UV4Jx
sOC7TxbmkQIDAQABo2MwYTAdBgNVHQ4EFgQU+1EuMRuOZ/ecsfYzNQ+yGZsxZrMw
HwYDVR0jBBgwFoAU+1EuMRuOZ/ecsfYzNQ+yGZsxZrMwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAf4wDQYJKoZIhvcNAQENBQADggIBACz38SkKR1WsEZnX
x1BKaS5/oQPw+7quDQCKGoD2Vz7CR7yQh4zQn/Hh0173vKvRWcwN2io0iLJ1ysv5
jXBLeWZh3djiQlXP3iWp4s01SiUwmFssxi3SD1IT2jNosk1xcVWthle9zth7Y8Mp
iUJYnHobP7tX7H2g+I8Rqw2sEX/yPSYMYcdH5a1xRMPOLHTyOaCgevRBBBtXkiAJ
Ob9QKZTaFaXntPXBKNSGkVb2d+2qKyJMrwd0KNI+SVSoIgNDAxkNOdi9x6X6ETW2
4aYFsytohFVkNUXx2eFYRim4yjnD8PHIvDQSofLfSAC5TOERtwUFd+Mw3/di+HCm
50OJPyoxZLjWQCCfNUZzgZZOe+zT6lgBiV3KB0UuuAdq7jGUeH/328HJDi30BvNj
+TNb9Hmpm+ZDguM+f8p7GxapX8AVNu/xErtl4msYiVJrr1qqV+qLLEMwIz0raujG
FFDd6N43wgduffbU20pThry0Y7rku5+RZjUZe/T7ZL+NUKiqXAPufrkqVkjX/8T+
wyNZz8KkiQwkJthojpppa79FDxn/A2M8tt+FQqIONAUPR2m5nurVgftQH0z5ZtDB
YykUlkUiPOJNXoDOIkbpA7lW2wezeY4te+EiSeUZSE541N5QBwaItaonIZsIgn6C
pMnwChV9468oRE20bdqq9+Go7g4E
-----END CERTIFICATE-----"""

ICANN_ROOT_CA_CERTS = [ICANN_ROOT_CA, ICANN_ROOT_CA_V2]

URL_ROOT_ANCHORS = "https://data.iana.org/root-anchors/root-anchors.xml"
URL_ROOT_ANCHORS_SIGNATURE = "https://data.iana.org/root-anchors/root-anchors.p7s"
URL_ROOT_ZONE = "https://www.internic.net/domain/root.zone"
URL_RESOLVER_API = "https://dns.google.com/resolve?name=.&type=dnskey"


def die(*Strings: str) -> NoReturn:
    """Generic way to leave the program early"""
    sys.stderr.write("".join(Strings) + " Exiting.\n")
    exit(1)


def log(*args: Any, **kwargs: Any) -> None:
    """Print a status message to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def bytes_to_string(byte_array: bytes | str) -> str:
    """Convert bytes that are in ASCII into strings.
    This is used for content received over URLs."""
    if isinstance(byte_array, str):
        return byte_array
    return byte_array.decode("ascii")


def pem_bundle(certs: list[str]) -> str:
    """Join PEM certificates into the text of a CA file."""
    return "\n\n".join(certs) + "\n"


def write_out_file(file_name: str, file_contents: str | bytes) -> None:
    """Takes a name of a file and string or bytearray; returns nothing.
    Writes out a file that we got from a URL or string; backs up the file if it exists."""
    # Back up the current one if it is there
    if os.path.exists(file_name):
        now_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file_name = f"{file_name}.backup_{now_timestamp}"
        try:
            os.rename(file_name, backup_file_name)
        except:
            die(f"Failed to rename {file_name} to {backup_file_name}.")
    # Pick the mode string based on the type of contents
    filemode = "wt" if isinstance(file_contents, str) else "wb"
    try:
        with open(file_name, mode=filemode) as fobj:
            fobj.write(file_contents)
    except:
        die(f"Could not write out the file {file_name}.")


def dnskey_to_hex_of_hash(dnskey_dict: KskDict, hash_type: str) -> str:
    """Takes a DNSKEY dict and hash type (string), and returns the hex of the hash as a string"""
    hash_funcs = {"1": hashlib.sha1, "2": hashlib.sha256}
    if hash_type not in hash_funcs:
        die(f"A DNSKEY dict had a hash type of {hash_type}, which is unknown.")
    this_hash = hash_funcs[hash_type]()
    digest_content = bytearray()
    digest_content.append(0)  # Name of the zone, expressed in wire format
    digest_content.extend(
        struct.pack("!HBB", int(dnskey_dict["f"]), int(dnskey_dict["p"]), int(dnskey_dict["a"]))
    )
    key_bytes = base64.b64decode(str(dnskey_dict["k"]))
    digest_content.extend(key_bytes)
    this_hash.update(digest_content)
    return (this_hash.hexdigest()).upper()


def extract_ksks_from_trust_anchors(valid_trust_anchors: list[TrustAnchorDict]) -> list[KskDict]:
    """Extract and return the KSKs from the parsed trust anchors."""
    log("Extracting KSKs from trust anchor...")
    ksks: list[KskDict] = []
    for i, anchor in enumerate(valid_trust_anchors):
        if "PublicKey" not in anchor or "Flags" not in anchor:
            log(f"Trust anchor {i} does not include both PublicKey and Flags values.")
            continue
        ksks.append(
            {"f": anchor["Flags"], "p": 3, "a": anchor["Algorithm"], "k": anchor["PublicKey"]}
        )
    return ksks


def fetch_ksk() -> list[KskDict]:
    """Return the KSKs, or die if they can't be found in via Google nor the zone file"""
    log("Fetching via Google Public DNS...")
    ksks = fetch_ksk_from_google()
    if ksks is None:
        log("Fetching via Google Public DNS failed. Fetching via the root zone file...")
        ksks = fetch_ksk_from_zonefile()
        if ksks is None:
            die("Could not fetch the KSKs from Google Public DNS nor get the root zone file.")
    if len(ksks) == 0:
        die("No KSKs were found.")
    return ksks


def fetch_ksk_from_google() -> list[KskDict] | None:
    """Return the root KSK via Google DNS-over-HTTPS. Returns None if there are errors."""
    ksks: list[KskDict] = []
    try:
        url = urlopen(URL_RESOLVER_API)
    except Exception as this_exception:
        log(
            f"Was not able to open URL {URL_RESOLVER_API}."
            f" The returned text was '{this_exception}'."
        )
        return None
    try:
        data = json.loads(url.read().decode("utf-8"))
    except Exception as this_exception:
        log(f"The JSON returned from Google DNS-over-HTTPS was not readable: {this_exception}")
        return None
    for answer in data["Answer"]:
        if answer["type"] == 48:
            (flags, proto, alg, key_b64) = re.split(r"\s+", answer["data"])
            if flags == "257":
                ksks.append({"f": flags, "p": proto, "a": alg, "k": key_b64})
    return ksks


def fetch_ksk_from_zonefile() -> list[KskDict] | None:
    """Rethurn the root KSK from the root zone file. Returns None if there are errors."""
    ksks: list[KskDict] = []
    try:
        url = urlopen(URL_ROOT_ZONE)
    except Exception as this_exception:
        log(f"Was not able to open URL {URL_ROOT_ZONE}. The returned text was '{this_exception}'.")
        return None
    for line in url.read().decode("utf-8").split("\n"):
        if "DNSKEY\t" in line:
            (_, _, _, _, flags, proto, alg, key_b64) = re.split(r"\s+", line)
            if flags == "257":
                ksks.append({"f": flags, "p": proto, "a": alg, "k": key_b64})
    return ksks


def openssl_version() -> str:
    """Return the local openssl's version line, e.g. "OpenSSL 3.0.13 30 Jan 2024";
    dies if `openssl version` fails."""
    result = subprocess.run(
        ["openssl", "version"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    version = result.stdout.strip()
    if result.returncode != 0 or not version:
        detail = f": {result.stderr.strip()}" if result.stderr.strip() else ""
        die(f"Could not run 'openssl version' (exit code {result.returncode}){detail}.")
    return version


def verification_options(version: str, make_empty_dir: Callable[[], str]) -> list[str]:
    """Return the openssl smime options that stop it trusting anything but -CAfile:
    the default CA directory and, on OpenSSL 3, the default CA store.
    make_empty_dir is called only when an empty directory is needed."""
    if version.startswith("LibreSSL "):
        # LibreSSL has no -no-CApath; point -CApath at an empty directory instead.
        return ["-CApath", make_empty_dir()]

    match = re.match(r"^OpenSSL (\d+)\.(\d+)", version)
    if not match:
        raise ValueError(f"Unsupported openssl: {version!r}")

    major, minor = map(int, match.groups())

    if major >= 3:
        return ["-no-CApath", "-no-CAstore"]
    if major == 1 and minor == 1:
        return ["-no-CApath"]

    raise ValueError(f"Unsupported openssl: {version!r}")


def validate_detached_signature(
    contents_filename: str,
    signature_filename: str,
    ca_filename: str,
    at_time: datetime.datetime | None = None,
    system_trust_options: list[str] | None = None,
) -> None:
    """Takes the name of the contents file, the signature file, and CA file;
    returns nothing if sucessful or dies if openssl returns an error.
    The CA file may hold several certificates; any of them can anchor the signature.
    Only the certificates in the CA file are trusted, not the system's CA certificates:
    the openssl options for that are chosen from the openssl version, unless
    system_trust_options is given, which replaces them.
    at_time (timezone-aware) checks certificate validity at that time instead of now;
    used by tests."""
    version = openssl_version()
    with contextlib.ExitStack() as temp_dirs:

        def make_empty_dir() -> str:
            empty_dir = temp_dirs.enter_context(tempfile.TemporaryDirectory(prefix="empty_"))
            log(f"Created empty directory {empty_dir} for -CApath.")
            return empty_dir

        if system_trust_options is not None:
            trust_options = system_trust_options
            log(
                f"WARNING: using {version} with --system-trust-options"
                f" ({' '.join(trust_options) or 'none'}) instead of the options this tool chooses."
            )
        else:
            try:
                trust_options = verification_options(version, make_empty_dir)
            except ValueError as this_exception:
                die(
                    f"{this_exception}. Use --system-trust-options to give the openssl"
                    " options that stop it trusting the system's CA certificates."
                )
            log(f"Using {version}.")
        validate_command = [
            "openssl",
            "smime",
            "-verify",
            "-CAfile",
            ca_filename,
            *trust_options,
            "-inform",
            "der",
            "-in",
            signature_filename,
            "-content",
            contents_filename,
        ]
        if at_time is not None:
            validate_command += ["-attime", str(int(at_time.timestamp()))]
        # An argument list, not a shell command; --system-trust-options are passed as given.
        validate_result = subprocess.run(  # noqa: S603
            validate_command, capture_output=True, check=False
        )
    if validate_result.returncode != 0:
        die(
            f"When running openssl, the return code was {validate_result.returncode} ",
            f"and the output was the following.\n{validate_result.stderr} {validate_result.stdout}",
        )
    else:
        log("Validation of the signature over the file succeeded.")


def extract_trust_anchors_from_xml(trust_anchor_xml: bytes | str) -> list[TrustAnchorDict]:
    """Takes a bytestring with the XML from IANA; returns a list of trust anchors."""
    # Turn the bytes from trust_anchor_xml into a string
    trust_anchor_xml_string = bytes_to_string(trust_anchor_xml)
    # Sanity check: make sure there is enough text in the returned stuff
    if len(trust_anchor_xml_string) < 100:
        die(f"The XML was too short: {len(trust_anchor_xml_string)} chars.")
    # Get the tree
    trust_anchor_tree = xml.etree.ElementTree.ElementTree(
        xml.etree.ElementTree.fromstring(trust_anchor_xml_string)  # noqa: S314
    )
    # Get all the KeyDigest elements
    digest_elements = trust_anchor_tree.findall(".//KeyDigest")
    log(f"There were {len(digest_elements)} KeyDigest elements in the trust anchor file.")
    trust_anchors: list[TrustAnchorDict] = []
    # Collect the values for the KeyDigest subelements and attributes
    for count, this_digest_element in enumerate(digest_elements):
        digest_value_dict: TrustAnchorDict = {}
        for this_subelement in ["KeyTag", "Algorithm", "DigestType", "Digest"]:
            sub_element = this_digest_element.find(this_subelement)
            if sub_element is None or sub_element.text is None:
                die(f"Did not find {this_subelement} element in a KeyDigest in a trust anchor.")
            digest_value_dict[this_subelement] = sub_element.text
        # Optional values
        for this_subelement in ["PublicKey", "Flags"]:
            value = this_digest_element.find(this_subelement)
            if value is None:
                continue
            digest_value_dict[this_subelement] = value.text or ""
        for this_attribute in ["validFrom", "validUntil"]:
            digest_value_dict[this_attribute] = this_digest_element.get(this_attribute, "")
        # Save this to the global trust_anchors list
        log(f"Added the trust anchor {count} to the list:\n{pprint.pformat(digest_value_dict)}")
        trust_anchors.append(digest_value_dict)
    if len(trust_anchors) == 0:
        die("There were no trust anchors found in the XML file.")
    return trust_anchors


def get_valid_trust_anchors(trust_anchors: list[TrustAnchorDict]) -> list[TrustAnchorDict]:
    """Takes a list of trust anchors; returns the list of trust anchors that are valid"""
    # Keep a list of just the valid trust anchors because some things are not going to go into it.
    valid_trust_anchors: list[TrustAnchorDict] = []
    now_datetime = datetime.datetime.now()
    for count, this_anchor in enumerate(trust_anchors):
        # Check the validity times; these only need to be accurate within a day or so
        if this_anchor["validFrom"] == "":
            log(
                f"Trust anchor {count}: the validFrom attribute is empty,",
                "so not using this trust anchor.",
            )
            continue
        from_date_time = datetime.datetime.fromisoformat(this_anchor["validFrom"].split("T", 2)[0])
        if now_datetime < from_date_time:
            log(
                f"Trust anchor {count}: the validFrom '{from_date_time}' is later",
                "than today, so not using this trust anchor.",
            )
            continue
        if this_anchor["validUntil"] == "":
            log(
                f"Trust anchor {count}: there was no validUntil attribute,",
                "so the validity is OK.",
            )
            valid_trust_anchors.append(this_anchor)
        else:
            until_date_time = datetime.datetime.fromisoformat(
                this_anchor["validUntil"].split("T", 2)[0]
            )
            if now_datetime > until_date_time:
                log(
                    f"Trust anchor {count}: the validUntil '{until_date_time}' is before ",
                    "today, so not using this trust anchor.",
                )
                continue
            log(f"Trust anchor {count}: the validity period passes.")
            valid_trust_anchors.append(this_anchor)
    if len(valid_trust_anchors) == 0:
        die("After checking validity dates, there were no trust anchors left.")
    log(f"After the date validity checks, there are now {len(valid_trust_anchors)} records.")
    return valid_trust_anchors


def get_matching_ksk(
    ksk_records: list[KskDict], valid_trust_anchors: list[TrustAnchorDict]
) -> list[KskDict]:
    """Takes in a list of KSKs and a list of trust anchors; returns a list of the KSKs"""
    matched_ksks: list[KskDict] = []
    for this_ksk_record in ksk_records:
        try:
            # check base64 syntax
            base64.b64decode(str(this_ksk_record["k"]))
        except:
            key_str = str(this_ksk_record["k"])
            die(f"The KSK '{key_str[0:15]}...{key_str[-15:]}' had bad Base64.")
        for count, this_trust_anchor in enumerate(valid_trust_anchors):
            hash_as_hex = dnskey_to_hex_of_hash(this_ksk_record, this_trust_anchor["DigestType"])
            if hash_as_hex == this_trust_anchor["Digest"]:
                key_b64 = str(this_ksk_record["k"])
                log(f"Trust anchor {count} matched KSK '{key_b64[0:15]}...{key_b64[-15:]}'")
                matched_ksks.append(this_ksk_record)
                break  # Don't check more trust anchors against this KSK
    if len(matched_ksks) == 0:
        die("After checking for trust anchor matches, there were no trusted KSKs.")
    log(f"There were {len(matched_ksks)} matched KSKs.")
    return matched_ksks


def format_records(valid_ksks: list[KskDict]) -> tuple[str, str]:
    """Takes a list of KSKs; returns (dnskey_records, ds_records) as strings."""
    dnskey_record_contents = ""
    ds_record_contents = ""

    for this_matched_ksk in valid_ksks:
        # Format the DNSKEY
        dnskey_record_contents += (
            f". IN DNSKEY {this_matched_ksk['f']} {this_matched_ksk['p']}"
            f" {this_matched_ksk['a']} {this_matched_ksk['k']}\n"
        )
        # Format the DS
        hash_as_hex = dnskey_to_hex_of_hash(this_matched_ksk, "2")  # Always do SHA256
        # Calculate the keytag
        tag_base = bytearray()
        tag_base.extend(
            struct.pack(
                "!HBB",
                int(this_matched_ksk["f"]),
                int(this_matched_ksk["p"]),
                int(this_matched_ksk["a"]),
            )
        )
        key_bytes = base64.b64decode(str(this_matched_ksk["k"]))
        tag_base.extend(key_bytes)
        accumulator = 0
        for counter, this_byte in enumerate(tag_base):
            if (counter % 2) == 0:
                accumulator += this_byte << 8
            else:
                accumulator += this_byte
        this_key_tag = ((accumulator & 0xFFFF) + (accumulator >> 16)) & 0xFFFF
        log(f"The key tag for this KSK is {this_key_tag}")
        ds_record_contents += f". IN DS {this_key_tag} {this_matched_ksk['a']} 2 {hash_as_hex}\n"

    return dnskey_record_contents, ds_record_contents


def export_ksk(
    valid_ksks: list[KskDict], ds_record_filename: str, dnskey_record_filename: str
) -> None:
    """Takes a list of KSKs; returns nothing but writes out files"""
    dnskey_record_contents, ds_record_contents = format_records(valid_ksks)

    log(f"Writing out {dnskey_record_filename}.")
    write_out_file(dnskey_record_filename, dnskey_record_contents)

    log(f"Writing out {ds_record_filename}.")
    write_out_file(ds_record_filename, ds_record_contents)


def main() -> int:
    """Main function"""

    # Where the files we create are kept
    (_, trust_anchor_filename) = tempfile.mkstemp(prefix="trust_anchor_")
    temp_files = [trust_anchor_filename]
    dnskey_record_filename = "ksk-as-dnskey.txt"
    ds_record_filename = "ksk-as-ds.txt"

    cmd_parse = argparse.ArgumentParser(
        prog="get-trust-anchor", description="DNSSEC Trust Anchor Tool"
    )
    cmd_parse.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    cmd_parse.add_argument(
        "--local",
        dest="local",
        type=str,
        help="Name of local file to use instead of getting the trust anchor from the URL",
    )
    cmd_parse.add_argument(
        "--local-sig",
        dest="local_sig",
        type=str,
        help="Name of local file to use instead of getting the trust anchor signature from the URL",
    )
    cmd_parse.add_argument(
        "--root-ca",
        dest="root_ca",
        type=str,
        help="PEM file of CA certificates to use instead of the built-in ICANN CA certificates",
    )
    cmd_parse.add_argument(
        "--no-validation",
        dest="no_validation",
        action="store_true",
        help="Disable validation for remote or local files",
    )
    cmd_parse.add_argument(
        "--system-trust-options",
        type=shlex.split,
        metavar="OPTIONS",
        help="openssl smime options to use instead of the tool's version-based choice for "
        "excluding the system's CA certificates; use the = form, e.g. "
        '--system-trust-options="-no-CApath -no-CAstore", or "" for none',
    )
    cmd_parse.add_argument(
        "--ksks-from-trust-anchor",
        dest="ksks_from_trust_anchor",
        action="store_true",
        help="Use the KSKs from the trust anchor instead of from DNS.",
    )
    cmd_parse.add_argument(
        "--keep",
        dest="keep",
        action="store_true",
        help="Keep the temporary files (the XML and validating signature",
    )
    cmd_parse.add_argument(
        "--print-dnskey",
        dest="print_dnskey",
        action="store_true",
        help="Print DNSKEY records to stdout instead of writing files",
    )
    cmd_parse.add_argument(
        "--print-ds",
        dest="print_ds",
        action="store_true",
        help="Print DS records to stdout instead of writing files",
    )
    opts = cmd_parse.parse_args()

    # Make sure there is an "openssl" command in their shell path
    if shutil.which("openssl") is None:
        die("Could not find the 'openssl' command on this system.")

    ### Step 1. Fetch the trust anchor file from IANA using HTTPS
    trust_anchor_xml: str | bytes
    if opts.local:
        if not os.path.exists(opts.local):
            die(f"Could not find file {opts.local}.")
        try:
            trust_anchor_xml = open(opts.local).read()
        except:
            die(f"Could not read from file {opts.local}.")
    else:
        # Get the trust anchor file from its URL
        try:
            trust_anchor_url = urlopen(URL_ROOT_ANCHORS)
        except Exception as this_exception:
            die(
                f"Was not able to open URL {URL_ROOT_ANCHORS}."
                f" The returned text was '{this_exception}'."
            )
        trust_anchor_xml = trust_anchor_url.read()
        trust_anchor_url.close()
    write_out_file(trust_anchor_filename, trust_anchor_xml)

    ### Step 2. Fetch the S/MIME signature for the trust anchor file from
    ### IANA using HTTPS. Get the signature file from its URL, write it to disk.
    if opts.local_sig:
        if not os.path.exists(opts.local_sig):
            die(f"Could not find file {opts.local_sig}.")
        try:
            signature_filename = opts.local_sig
            signature_contents = open(opts.local_sig, mode="rb").read()
        except:
            die(f"Could not read from file {opts.local_sig}.")
    else:
        try:
            (_, signature_filename) = tempfile.mkstemp(prefix="signature_")
            temp_files.append(signature_filename)

            signature_url = urlopen(URL_ROOT_ANCHORS_SIGNATURE)
            signature_contents = signature_url.read()
            signature_url.close()
            write_out_file(signature_filename, signature_contents)
        except Exception as this_exception:
            die(
                f"Was not able to open URL {URL_ROOT_ANCHORS_SIGNATURE}."
                f" The returned text was '{this_exception}'."
            )

    ### Step 3. Validate the signature on the trust anchor file using the
    ### built-in ICANN CA certificates. Skip this step if --no-validation is given.
    if opts.root_ca:
        icann_ca_filename = opts.root_ca
    else:
        (_, icann_ca_filename) = tempfile.mkstemp(prefix="icann_ca_")
        temp_files.append(icann_ca_filename)
        write_out_file(icann_ca_filename, pem_bundle(ICANN_ROOT_CA_CERTS))
        log(f"Wrote the built-in ICANN CA certificates to {icann_ca_filename}.")

    if opts.no_validation is not True:
        validate_detached_signature(
            trust_anchor_filename,
            signature_filename,
            icann_ca_filename,
            system_trust_options=opts.system_trust_options,
        )
    else:
        log("Not validating the local trust anchor file.")

    ### Step 4. Extract the trust anchor key digests from the trust anchor file
    trust_anchors = extract_trust_anchors_from_xml(trust_anchor_xml)

    ### Step 5. Check the validity period for each digest
    valid_trust_anchors = get_valid_trust_anchors(trust_anchors)

    ### Step 6. Verify that the trust anchors match the published KSKs
    ### file.
    if opts.ksks_from_trust_anchor:
        ksk_records = extract_ksks_from_trust_anchors(valid_trust_anchors)
    else:
        ksk_records = fetch_ksk()
    for key in ksk_records:
        key_b64 = str(key["k"])
        log(f"Found KSK {key['f']} {key['p']} {key['a']} '{key_b64[:15]}...{key_b64[-15:]}'.")
    # Go trough all the KSKs, decoding them and comparing them to all the trust anchors
    matched_ksks = get_matching_ksk(ksk_records, valid_trust_anchors)

    ### Step 7. Write out the trust anchors as a DNSKEY and DS records.
    if opts.print_dnskey or opts.print_ds:
        dnskey_records, ds_records = format_records(matched_ksks)
        if opts.print_dnskey:
            sys.stdout.write(dnskey_records)
        if opts.print_ds:
            sys.stdout.write(ds_records)
    else:
        export_ksk(matched_ksks, ds_record_filename, dnskey_record_filename)
    # Delete the temporary files unless requested not to
    if opts.keep:
        log(f"Kept the temporary files: {' '.join(temp_files)}")
    else:
        log("Deleting the temporary files.")
        for this_file in temp_files:
            if os.path.exists(this_file):
                try:
                    os.unlink(this_file)
                except Exception as this_exception:
                    log(f"Could not delete {this_file}: '{this_exception}'. Continuing")

    return 0
