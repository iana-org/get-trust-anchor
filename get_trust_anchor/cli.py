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
    Step 3. Validate the signature on the trust anchor file using a built-in IANA CA key
    Step 4. Extract the trust anchor key digests from the trust anchor file
    Step 5. Check the validity period for each digest
    Step 6. Verify that the trust anchors match the KSK in the root zone file
    Step 7. Write out the trust anchors as a DNSKEY and DS records

Note that the validation is done against a built-in ICANN CA, not one retrieved through a
URL. This means that even if HTTPS authentication checking isn't done, the resulting
trust anchors are still cryptographically validated.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import pprint
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree
from typing import Any, NoReturn
from urllib.request import urlopen

# Type aliases
KskDict = dict[str, str | int]
TrustAnchorDict = dict[str, str]

ICANN_ROOT_CA_CERT = """
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
"""

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


def validate_detached_signature(
    contents_filename: str, signature_filename: str, ca_filename: str
) -> None:
    """Takes the name of the contents file, the signature file, and CA file;
    returns nothing if sucessful or dies if openssl returns an error."""
    # Run openssl to validate the signature
    validate_command = [
        "openssl",
        "smime",
        "-verify",
        "-CAfile",
        ca_filename,
        "-inform",
        "der",
        "-in",
        signature_filename,
        "-content",
        contents_filename,
    ]
    # Fixed command name and internally-generated file paths, not shell input.
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
        # Write out the DNSKEY
        dnskey_record_contents += (
            f". IN DNSKEY {this_matched_ksk['f']} {this_matched_ksk['p']}"
            f" {this_matched_ksk['a']} {this_matched_ksk['k']}\n"
        )
        # Write out the DS
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

    cmd_parse = argparse.ArgumentParser(description="DNSSEC Trust Anchor Tool")
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
        help="Name of local root anchor CA file instead of using built-in ICANN_ROOT_CA_CERT",
    )
    cmd_parse.add_argument(
        "--no-validation",
        dest="no_validation",
        action="store_true",
        help="Disable validation for remote or local files",
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
        # Get the trust anchor file from its URL, write it to disk
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

    ### Step 3. Validate the signature on the trust anchor file using a
    ### built-in IANA CA key. Skip this step if using a local file.
    if opts.root_ca:
        icann_ca_filename = opts.root_ca
    else:
        (_, icann_ca_filename) = tempfile.mkstemp(prefix="icann_ca_")
        temp_files.append(icann_ca_filename)
        write_out_file(icann_ca_filename, ICANN_ROOT_CA_CERT)

    if opts.no_validation is not True:
        validate_detached_signature(trust_anchor_filename, signature_filename, icann_ca_filename)
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
