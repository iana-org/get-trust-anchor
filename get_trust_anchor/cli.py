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
    that has just Python 3.x and the OpenSSL command line tool.

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

# pylint: disable=wrong-import-order,wrong-import-position,import-error,no-name-in-module,broad-except,bare-except,too-many-locals

import argparse
import base64
import codecs
import datetime
import hashlib
import json
import os
import pprint
import re
import struct
import sys
import tempfile
import xml.etree.ElementTree
from io import StringIO
from urllib.request import urlopen

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates

ICANN_ROOT_CA_CERT = '''
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
'''

URL_ROOT_ANCHORS = "https://data.iana.org/root-anchors/root-anchors.xml"
URL_ROOT_ANCHORS_SIGNATURE = "https://data.iana.org/root-anchors/root-anchors.p7s"
URL_ROOT_ZONE = "https://www.internic.net/domain/root.zone"
URL_RESOLVER_API = "https://dns.google.com/resolve?name=.&type=dnskey"


def die(*Strings):
    """Generic way to leave the program early"""
    sys.stderr.write("".join(Strings) + " Exiting.\n")
    exit(1)


def bytes_to_string(byte_array):
    """Convert bytes that are in ASCII into strings.
        This is used for content received over URLs."""
    if isinstance(byte_array, str):
        return str(byte_array)
    ascii_codec = codecs.lookup("ascii")
    return ascii_codec.decode(byte_array)[0]


def write_out_file(file_name, file_contents):
    """Takes a name of a file and string or bytearray; returns nothing.
        Writes out a file that we got from a URL or string; backs up the file if it exists."""
    # Back up the current one if it is there
    if os.path.exists(file_name):
        now_timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file_name = "{}.backup_{}".format(file_name, now_timestamp)
        try:
            os.rename(file_name, backup_file_name)
        except:
            die("Failed to rename {} to {}.".format(file_name, backup_file_name))
    # Pick the mode string based on the type of contents
    if isinstance(file_contents, str):
        filemode = "wt"
    else:
        filemode = "wb"
    try:
        fobj = open(file_name, mode=filemode)
        fobj.write(file_contents)
        fobj.close()
    except:
        die("Could not write out the file {}.".format(file_name))
    return


def dnskey_to_hex_of_hash(dnskey_dict, hash_type):
    """Takes a DNSKEY dict and hash type (string), and returns the hex of the hash as a string"""
    if hash_type == "1":
        this_hash = hashlib.sha1()
    elif hash_type == "2":
        this_hash = hashlib.sha256()
    else:
        die("A DNSKEY dict had a hash type of {}, which is unknown.".format(hash_type))
    digest_content = bytearray()
    digest_content.append(0)  # Name of the zone, expressed in wire format
    digest_content.extend(struct.pack("!HBB", int(dnskey_dict["f"]),\
        int(dnskey_dict["p"]), int(dnskey_dict["a"])))
    key_bytes = base64.b64decode(dnskey_dict["k"])
    digest_content.extend(key_bytes)
    this_hash.update(digest_content)
    return (this_hash.hexdigest()).upper()


def extract_ksks_from_trust_anchors(valid_trust_anchors):
    """Extract and return the KSKs from the parsed trust anchors."""
    print("Extracting KSKs from trust anchor...")
    ksks = []
    for (i, anchor) in enumerate(valid_trust_anchors):
        if "PublicKey" not in anchor or "Flags" not in anchor:
            print("Trust anchor {} does not include both PublicKey and Flags values.".format(i))
            continue
        ksks.append({'f': anchor["Flags"], 'p': 3, 'a': anchor["Algorithm"], 'k': anchor["PublicKey"]})
    return ksks


def fetch_ksk():
    """Return the KSKs, or die if they can't be found in via Google nor the zone file"""
    print("Fetching via Google Public DNS...")
    ksks = fetch_ksk_from_google()
    if ksks is None:
        print("Fetching via Google Public DNS failed. Fetching via the root zone file...")
        ksks = fetch_ksk_from_zonefile()
        if ksks is None:
            die("Could not fetch the KSKs from Google Public DNS nor get the root zone file.")
    if len(ksks) == 0:
        die("No KSKs were found.")
    return ksks


def fetch_ksk_from_google():
    """Return the root KSK via Google DNS-over-HTTPS. Returns None if there are errors."""
    ksks = []
    try:
        url = urlopen(URL_RESOLVER_API)
    except Exception as this_exception:
        print("Was not able to open URL {}. The returned text was '{}'.".format(\
            URL_RESOLVER_API, this_exception))
        return None
    try:
        data = json.loads(url.read().decode('utf-8'))
    except Exception as this_exception:
        print("The JSON returned from Google DNS-over-HTTPS was not readable: {}".format(\
            this_exception))
        return None
    for answer in data['Answer']:
        if answer['type'] == 48:
            (flags, proto, alg, key_b64) = re.split(r"\s+", answer['data'])
            if flags == '257':
                ksks.append({'f': flags, 'p': proto, 'a': alg, 'k': key_b64})
    return ksks


def fetch_ksk_from_zonefile():
    """Rethurn the root KSK from the root zone file. Returns None if there are errors."""
    ksks = []
    try:
        url = urlopen(URL_ROOT_ZONE)
    except Exception as this_exception:
        print("Was not able to open URL {}. The returned text was '{}'.".format(\
            URL_ROOT_ZONE, this_exception))
        return None
    for line in url.read().decode('utf-8').split('\n'):
        if "DNSKEY\t" in line:
            (_, _, _, _, flags, proto, alg, key_b64) = re.split(r"\s+", line)
            if flags == '257':
                ksks.append({'f': flags, 'p': proto, 'a': alg, 'k': key_b64})
    return ksks


def _der_read(data, offset):
    """Read a DER TLV at offset. Returns (tag, value_bytes, next_offset)."""
    tag = data[offset]
    offset += 1
    length_byte = data[offset]
    offset += 1
    if length_byte < 0x80:
        length = length_byte
    else:
        num_bytes = length_byte & 0x7f
        length = int.from_bytes(data[offset:offset + num_bytes], 'big')
        offset += num_bytes
    return tag, data[offset:offset + length], offset + length


def _der_elements(data):
    """Yield (tag, value) for each TLV element in a DER SEQUENCE/SET body."""
    offset = 0
    while offset < len(data):
        tag, value, offset = _der_read(data, offset)
        yield tag, value


def _der_encode_length(length):
    """Encode a length value in DER format."""
    if length < 0x80:
        return bytes([length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(length_bytes)]) + length_bytes


# OID for messageDigest attribute (1.2.840.113549.1.9.4)
_OID_MESSAGE_DIGEST = b'\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04'

# Digest algorithm OIDs to cryptography hash classes
_DIGEST_ALGORITHMS = {
    b'\x60\x86\x48\x01\x65\x03\x04\x02\x01': hashes.SHA256,  # 2.16.840.1.101.3.4.2.1
    b'\x2b\x0e\x03\x02\x1a': hashes.SHA1,  # 1.3.14.3.2.26
}


def _extract_pkcs7_signer_info(der_data):
    """Parse a DER-encoded PKCS7 SignedData and extract the first SignerInfo.

    Returns a dict with keys: digest_algorithm, auth_attrs_value,
    message_digest, signature."""
    # ContentInfo SEQUENCE -> find [0] EXPLICIT containing SignedData
    _, ci_body, _ = _der_read(der_data, 0)
    signed_data_wrapper = None
    for tag, value in _der_elements(ci_body):
        if tag == 0xa0:
            signed_data_wrapper = value
            break
    if signed_data_wrapper is None:
        raise ValueError("No SignedData found in PKCS7")

    # SignedData SEQUENCE -> find signerInfos (last SET)
    _, sd_body, _ = _der_read(signed_data_wrapper, 0)
    last_set = None
    for tag, value in _der_elements(sd_body):
        if tag == 0x31:  # SET (first is digestAlgorithms, last is signerInfos)
            last_set = value
    if last_set is None:
        raise ValueError("No signerInfos found")

    # First SignerInfo SEQUENCE
    _, si_body, _ = _der_read(last_set, 0)
    si_elements = list(_der_elements(si_body))

    result = {}

    # digestAlgorithm is the second SEQUENCE (first is sid/issuerAndSerialNumber)
    seq_count = 0
    for tag, value in si_elements:
        if tag == 0x30:
            seq_count += 1
            if seq_count == 2:  # digestAlgorithm
                for oid_tag, oid_value in _der_elements(value):
                    if oid_tag == 0x06:
                        result['digest_algorithm'] = oid_value
                        break
                break

    # [0] authenticatedAttributes and OCTET STRING signature
    for tag, value in si_elements:
        if tag == 0xa0:
            result['auth_attrs_value'] = value
            # Find messageDigest attribute inside the authenticated attributes
            for attr_tag, attr_value in _der_elements(value):
                if attr_tag != 0x30:
                    continue
                attr_parts = list(_der_elements(attr_value))
                if len(attr_parts) >= 2 and attr_parts[0][1] == _OID_MESSAGE_DIGEST:
                    # Value is in a SET containing an OCTET STRING
                    for vt, vv in _der_elements(attr_parts[1][1]):
                        if vt == 0x04:
                            result['message_digest'] = vv
                            break
        elif tag == 0x04:
            result['signature'] = value

    return result


def validate_detached_signature(content, signature_der, ca_pem):
    """Verify a DER-encoded PKCS7 detached signature against a CA certificate.

    Args:
        content: the signed content (bytes or str)
        signature_der: DER-encoded PKCS7 signature (bytes)
        ca_pem: PEM-encoded CA certificate (str)
    """
    if isinstance(content, str):
        content = content.encode()
    if isinstance(ca_pem, str):
        ca_pem = ca_pem.encode()

    # Extract the signer certificate from the PKCS7 structure
    certs = load_der_pkcs7_certificates(signature_der)
    if not certs:
        die("No certificates found in the signature file.")
    signer_cert = certs[0]

    # Verify the signer certificate was issued by the CA
    ca_cert = x509.load_pem_x509_certificate(ca_pem)
    try:
        ca_cert.public_key().verify(
            signer_cert.signature,
            signer_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            signer_cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        die("The signer certificate was not issued by the trusted CA.")

    # Parse PKCS7 to extract signature verification data
    try:
        signer_info = _extract_pkcs7_signer_info(signature_der)
    except (ValueError, IndexError, KeyError) as exc:
        die("Failed to parse PKCS7 signature: {}".format(exc))

    if 'signature' not in signer_info:
        die("No signature found in PKCS7 signer info.")

    # Determine the digest algorithm
    alg_oid = signer_info.get('digest_algorithm')
    hash_class = _DIGEST_ALGORITHMS.get(alg_oid)
    if hash_class is None:
        die("Unsupported digest algorithm in signature.")

    if 'auth_attrs_value' in signer_info:
        # Verify content digest matches the messageDigest attribute
        content_digest = hashes.Hash(hash_class())
        content_digest.update(content)
        content_digest = content_digest.finalize()

        if signer_info.get('message_digest') != content_digest:
            die("Content digest does not match the messageDigest in the signature.")

        # Per RFC 2315, the signature is over the DER encoding of the
        # authenticated attributes re-tagged as a SET (0x31) rather than
        # the implicit [0] (0xa0) used in the SignerInfo structure.
        attrs = signer_info['auth_attrs_value']
        attrs_der = bytes([0x31]) + _der_encode_length(len(attrs)) + attrs

        try:
            signer_cert.public_key().verify(
                signer_info['signature'],
                attrs_der,
                padding.PKCS1v15(),
                hash_class(),
            )
        except InvalidSignature:
            die("PKCS7 signature verification failed.")
    else:
        # No authenticated attributes; verify signature directly over content
        try:
            signer_cert.public_key().verify(
                signer_info['signature'],
                content,
                padding.PKCS1v15(),
                hash_class(),
            )
        except InvalidSignature:
            die("PKCS7 signature verification failed.")

    print("Validation of the signature over the file succeeded.")


def extract_trust_anchors_from_xml(trust_anchor_xml):
    """Takes a bytestring with the XML from IANA; returns a list of trust anchors."""
    # Turn the bytes from trust_anchor_xml into a string
    trust_anchor_xml_string = bytes_to_string(trust_anchor_xml)
    # Sanity check: make sure there is enough text in the returned stuff
    if len(trust_anchor_xml_string) < 100:
        die("The XML was too short: {} chars.".format(len(trust_anchor_xml_string)))
    # ElementTree requries a file so use StringIO to turn the string into a file
    trust_anchor_as_file = StringIO(trust_anchor_xml_string)
    # Get the tree
    trust_anchor_tree = xml.etree.ElementTree.ElementTree(file=trust_anchor_as_file)
    # Get all the KeyDigest elements
    digest_elements = trust_anchor_tree.findall(".//KeyDigest")
    print("There were {} KeyDigest elements in the trust anchor file.".format(\
        len(digest_elements)))
    trust_anchors = []  # Global list of dicts that is taken from the XML file
    # Collect the values for the KeyDigest subelements and attributes
    for (count, this_digest_element) in enumerate(digest_elements):
        digest_value_dict = {}
        for this_subelement in ["KeyTag", "Algorithm", "DigestType", "Digest"]:
            try:
                this_key_tag_text = (this_digest_element.find(this_subelement)).text
            except:
                die("Did not find {} element in a KeyDigest in a trust anchor.".format(\
                    this_subelement))
            digest_value_dict[this_subelement] = this_key_tag_text
        # Optional values
        for this_subelement in ["PublicKey", "Flags"]:
            value = this_digest_element.find(this_subelement)
            if value is None:
                continue
            digest_value_dict[this_subelement] = value.text
        for this_attribute in ["validFrom", "validUntil"]:
            if this_attribute in this_digest_element.keys():
                digest_value_dict[this_attribute] = this_digest_element.attrib[this_attribute]
            else:
                digest_value_dict[this_attribute] = ""  # Missing attributes get empty values
        # Save this to the global trust_anchors list
        print("Added the trust anchor {} to the list:\n{}".format(count, pprint.pformat(\
            digest_value_dict)))
        trust_anchors.append(digest_value_dict)
    if len(trust_anchors) == 0:
        die("There were no trust anchors found in the XML file.")
    return trust_anchors


def get_valid_trust_anchors(trust_anchors):
    """Takes a list of trust anchors; returns the list of trust anchors that are valid"""
    # Keep a list of just the valid trust anchors because some things are not going to go into it.
    valid_trust_anchors = []
    now_datetime = datetime.datetime.now()
    for (count, this_anchor) in enumerate(trust_anchors):
        # Check the validity times; these only need to be accurate within a day or so
        if this_anchor["validFrom"] == "":
            print("Trust anchor {}: the validFrom attribute is empty,".format(count),\
                "so not using this trust anchor.")
            continue
        digest_element_valid_from = this_anchor["validFrom"]
        (from_left, _) = digest_element_valid_from.split("T", 2)
        (from_year, from_month, from_day) = from_left.split("-")
        from_date_time = datetime.datetime(int(from_year), int(from_month), int(from_day))
        if now_datetime < from_date_time:
            print("Trust anchor {}: the validFrom '{}' is later".format(count, from_date_time),\
                "than today, so not using this trust anchor.")
            continue
        if this_anchor["validUntil"] == "":
            print("Trust anchor {}: there was no validUntil attribute,".format(count),\
                "so the validity is OK.")
            valid_trust_anchors.append(this_anchor)
        else:
            digest_element_valid_until = this_anchor["validUntil"]
            (until_left, _) = digest_element_valid_until.split("T", 2)
            (until_year, until_month, until_day) = until_left.split("-")
            until_date_time = datetime.datetime(int(until_year), int(until_month), int(until_day))
            if now_datetime > until_date_time:
                print("Trust anchor {}: the validUntil '{}' is before ".format(count,\
                     until_date_time), "today, so not using this trust anchor.")
                continue
            else:
                print("Trust anchor {}: the validity period passes.".format(count))
                valid_trust_anchors.append(this_anchor)
    if len(valid_trust_anchors) == 0:
        die("After checking validity dates, there were no trust anchors left.")
    print("After the date validity checks, there are now {} records.".format(\
        len(valid_trust_anchors)))
    return valid_trust_anchors


def get_matching_ksk(ksk_records, valid_trust_anchors):
    """Takes in a list of KSKs and a list of trust anchors; returns a list of the KSKs"""
    matched_ksks = []
    for this_ksk_record in ksk_records:
        try:
            # check base64 syntax
            base64.b64decode(this_ksk_record["k"])
        except:
            die("The KSK '{}...{}' had bad Base64.".format(\
                this_ksk_record[0:15], this_ksk_record[-15:]))
        for (count, this_trust_anchor) in enumerate(valid_trust_anchors):
            hash_as_hex = dnskey_to_hex_of_hash(this_ksk_record, this_trust_anchor["DigestType"])
            if hash_as_hex == this_trust_anchor["Digest"]:
                print("Trust anchor {} matched KSK '{}...{}'".format(count,\
                    this_ksk_record["k"][0:15], this_ksk_record["k"][-15:]))
                matched_ksks.append(this_ksk_record)
                break  # Don't check more trust anchors against this KSK
    if len(matched_ksks) == 0:
        die("After checking for trust anchor matches, there were no trusted KSKs.")
    else:
        print("There were {} matched KSKs.".format(len(matched_ksks)))
    return matched_ksks


def export_ksk(valid_ksks, ds_record_filename, dnskey_record_filename):
    """Takes a list of KSKs; returns nothing but writes out files"""
    ##############################
    # Still to do:
    #   BIND output formats
    ##############################

    dnskey_record_contents = ""
    ds_record_contents = ""

    for this_matched_ksk in valid_ksks:
        # Write out the DNSKEY
        dnskey_record_contents += ". IN DNSKEY {flags} {proto} {alg} {keyas64}\n".format(\
            flags=this_matched_ksk["f"], proto=this_matched_ksk["p"],\
            alg=this_matched_ksk["a"], keyas64=this_matched_ksk["k"])
        # Write out the DS
        hash_as_hex = dnskey_to_hex_of_hash(this_matched_ksk, "2")  # Always do SHA256
        # Calculate the keytag
        tag_base = bytearray()
        tag_base.extend(struct.pack("!HBB", int(this_matched_ksk["f"]), int(this_matched_ksk["p"]),\
            int(this_matched_ksk["a"])))
        key_bytes = base64.b64decode(this_matched_ksk["k"])
        tag_base.extend(key_bytes)
        accumulator = 0
        for (counter, this_byte) in enumerate(tag_base):
            if (counter % 2) == 0:
                accumulator += (this_byte << 8)
            else:
                accumulator += this_byte
        this_key_tag = ((accumulator & 0xFFFF) + (accumulator>>16)) & 0xFFFF
        print("The key tag for this KSK is {}".format(this_key_tag))
        ds_record_contents += ". IN DS {keytag} {alg} 2 {sha256ofkey}\n".format(\
            keytag=this_key_tag, alg=this_matched_ksk["a"],\
            sha256ofkey=hash_as_hex)

    print("Writing out {}.".format(dnskey_record_filename))
    write_out_file(dnskey_record_filename, dnskey_record_contents)

    print("Writing out {}.".format(ds_record_filename))
    write_out_file(ds_record_filename, ds_record_contents)


def main():
    """Main function"""

    # Where the files we create are kept
    (_, trust_anchor_filename) = tempfile.mkstemp(prefix="trust_anchor_")
    temp_files = [trust_anchor_filename]
    dnskey_record_filename = "ksk-as-dnskey.txt"
    ds_record_filename = "ksk-as-ds.txt"

    cmd_parse = argparse.ArgumentParser(description="DNSSEC Trust Anchor Tool")
    cmd_parse.add_argument("--local", dest="local", type=str,\
        help="Name of local file to use instead of getting the trust anchor from the URL")
    cmd_parse.add_argument("--local-sig", dest="local_sig", type=str,\
        help="Name of local file to use instead of getting the trust anchor signature from the URL")
    cmd_parse.add_argument("--root-ca", dest="root_ca", type=str,\
        help="Name of local root anchor CA file instead of using built-in ICANN_ROOT_CA_CERT")
    cmd_parse.add_argument("--no-validation", dest="no_validation", action='store_true',\
        help="Disable validation for remote or local files")
    cmd_parse.add_argument("--ksks-from-trust-anchor", dest="ksks_from_trust_anchor", action='store_true',\
        help="Use the KSKs from the trust anchor instead of from DNS.")
    cmd_parse.add_argument("--keep", dest="keep", action='store_true',\
        help="Keep the temporary files (the XML and validating signature")
    opts = cmd_parse.parse_args()

    ### Step 1. Fetch the trust anchor file from IANA using HTTPS
    if opts.local:
        if not os.path.exists(opts.local):
            die("Could not find file {}.".format(opts.local))
        try:
            trust_anchor_xml = open(opts.local, mode="rt").read()
        except:
            die("Could not read from file {}.".format(opts.local))
    else:
        # Get the trust anchor file from its URL
        try:
            trust_anchor_url = urlopen(URL_ROOT_ANCHORS)
        except Exception as this_exception:
            die("Was not able to open URL {}. The returned text was '{}'.".format(\
                URL_ROOT_ANCHORS, this_exception))
        trust_anchor_xml = trust_anchor_url.read()
        trust_anchor_url.close()
    write_out_file(trust_anchor_filename, trust_anchor_xml)

    ### Step 2. Fetch the S/MIME signature for the trust anchor file from
    ### IANA using HTTPS.
    signature_contents = None
    if opts.local_sig:
        if not os.path.exists(opts.local_sig):
            die("Could not find file {}.".format(opts.local_sig))
        try:
            signature_contents = open(opts.local_sig, mode="rb").read()
        except:
            die("Could not read from file {}.".format(opts.local_sig))
    else:
        try:
            (_, signature_filename) = tempfile.mkstemp(prefix="signature_")
            temp_files.append(signature_filename)

            signature_url = urlopen(URL_ROOT_ANCHORS_SIGNATURE)
            signature_contents = signature_url.read()
            signature_url.close()
            write_out_file(signature_filename, signature_contents)
        except Exception as this_exception:
            die("Was not able to open URL {}. returned text was '{}'.".format(\
                URL_ROOT_ANCHORS_SIGNATURE, this_exception))

    ### Step 3. Validate the signature on the trust anchor file using a
    ### built-in IANA CA key.
    if not opts.no_validation:
        if opts.root_ca:
            try:
                ca_pem = open(opts.root_ca, mode="rt").read()
            except:
                die("Could not read CA file {}.".format(opts.root_ca))
        else:
            ca_pem = ICANN_ROOT_CA_CERT
        validate_detached_signature(trust_anchor_xml, signature_contents, ca_pem)
    else:
        print("Not validating the local trust anchor file.")

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
        print("Found KSK {flags} {proto} {alg} '{keystart}...{keyend}'.".format(\
            flags=key['f'], proto=key['p'], alg=key['a'],
            keystart=key['k'][0:15], keyend=key['k'][-15:]))
    # Go trough all the KSKs, decoding them and comparing them to all the trust anchors
    matched_ksks = get_matching_ksk(ksk_records, valid_trust_anchors)

    ### Step 7. Write out the trust anchors as a DNSKEY and DS records.
    export_ksk(matched_ksks, ds_record_filename, dnskey_record_filename)
    # Delete the temporary files unless requested not to
    if opts.keep:
        print("Kept the temporary files: {}".format(" ".join(temp_files)))
    else:
        print("Deleting the temporary files.")
        for this_file in temp_files:
            if os.path.exists(this_file):
                try:
                    os.unlink(this_file)
                except Exception as this_exception:
                    print("Could not delete {}: '{}'. Continuing".format(this_file, this_exception))

    return 0
