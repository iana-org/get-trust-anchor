#!/usr/bin/env python
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
DNSSEC Trust Anchor Fetcher (get_trust_anchor.py)

This tool writes out a copy of the current DNSSEC trust anchor.
    The primary design goal for this software is that it should be able to be run on any system
    that has just Python (either 2.7 or 3.x) and the OpenSSL command line tool.

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

from __future__ import print_function

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
import subprocess
import sys
import tempfile
import xml.etree.ElementTree

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

PYTHON_MAJOR = int(sys.version_info[0])
PYTHON_MINOR = int(sys.version_info[1])
if (PYTHON_MAJOR == 2) and (PYTHON_MINOR != 7):
    die("If this program is running in Python 2, it must be Python 2.7.")

# Get the urlopen and StringIO functions
if PYTHON_MAJOR == 2:
    from urllib2 import urlopen
    from StringIO import StringIO
else:
    from urllib.request import urlopen
    from io import StringIO


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


def validate_detached_signature(contents_filename, signature_filename, ca_filename):
    """Takes the name of the contents file, the signature file, and CA file;
        returns nothing if sucessful or dies if openssl returns an error."""
    # Run openssl to validate the signature
    validate_command = "openssl smime -verify -CAfile {ca} -inform der -in {sig} -content {cont}"
    validate_popen = subprocess.Popen(validate_command.format(\
        ca=ca_filename, sig=signature_filename, cont=contents_filename),\
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (validate_out, validate_err) = validate_popen.communicate()
    if validate_popen.returncode != 0:
        die("When running openssl, the return code was {} ".format(validate_popen.returncode),\
            "and the output was the following.\n{} {}".format(validate_err, validate_out))
    else:
        print("Validation of the signature over the file succeeded.")


def extract_trust_anchors_from_xml(trust_anchor_xml):
    """Takes a bytestring with the XML from IANA; returns a list of trust anchors."""
    # Turn the bytes from trust_anchor_xml into a string
    trust_anchor_xml_string = bytes_to_string(trust_anchor_xml)
    # Sanity check: make sure there is enough text in the returned stuff
    if len(trust_anchor_xml_string) < 100:
        die("The XML was too short: {} chars.".format(len(trust_anchor_xml_string)))
    # ElementTree requries a file so use StringIO to turn the string into a file
    try:
        trust_anchor_as_file = StringIO(trust_anchor_xml_string)  # This works for Python 3
    except:
        trust_anchor_as_file = StringIO(unicode(trust_anchor_xml_string))  # Needed for Python 2
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
    for this_matched_ksk in valid_ksks:
        # Write out the DNSKEY
        dnskey_record_contents = ". IN DNSKEY {flags} {proto} {alg} {keyas64}\n".format(\
            flags=this_matched_ksk["f"], proto=this_matched_ksk["p"],\
            alg=this_matched_ksk["a"], keyas64=this_matched_ksk["k"])
        print("Writing out {}.".format(dnskey_record_filename))
        write_out_file(dnskey_record_filename, dnskey_record_contents)
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
        ds_record_contents = ". IN DS {keytag} {alg} 2 {sha256ofkey}\n".format(\
            keytag=this_key_tag, alg=this_matched_ksk["a"],\
            sha256ofkey=hash_as_hex)
        print("Writing out {}.".format(ds_record_filename))
        write_out_file(ds_record_filename, ds_record_contents)


def main():
    """Main function"""

    # Where the files we create are kept
    (_, trust_anchor_filename) = tempfile.mkstemp(prefix="trust_anchor_")
    (_, signature_filename) = tempfile.mkstemp(prefix="signature_")
    (_, icann_ca_filename) = tempfile.mkstemp(prefix="icann_ca_")
    temp_files = [trust_anchor_filename, signature_filename, icann_ca_filename]
    dnskey_record_filename = "ksk-as-dnskey.txt"
    ds_record_filename = "ksk-as-ds.txt"

    cmd_parse = argparse.ArgumentParser(description="DNSSEC Trust Anchor Tool")
    cmd_parse.add_argument("--local", dest="local", type=str,\
        help="Name of local file to use instead of getting the trust anchor from the URL")
    cmd_parse.add_argument("--keep", dest="keep", action='store_true',\
        help="Keep the temporary files (the XML and validating signature")
    opts = cmd_parse.parse_args()

    # Make sure there is an "openssl" command in their shell path
    which_return = subprocess.call("which openssl", shell=True, stdout=subprocess.PIPE)
    if which_return != 0:
        die("Could not find the 'openssl' command on this system.")

    ### Step 1. Fetch the trust anchor file from IANA using HTTPS
    if opts.local:
        if not os.path.exists(opts.local):
            die("Could not find file {}.".format(opts.local))
        try:
            trust_anchor_xml = open(opts.local, mode="rt").read()
        except:
            die("Could not read from file {}.".format(opts.local))
    else:
        # Get the trust anchor file from its URL, write it to disk
        try:
            trust_anchor_url = urlopen(URL_ROOT_ANCHORS)
        except Exception as this_exception:
            die("Was not able to open URL {}. The returned text was '{}'.".format(\
                URL_ROOT_ANCHORS, this_exception))
        trust_anchor_xml = trust_anchor_url.read()
        trust_anchor_url.close()
    write_out_file(trust_anchor_filename, trust_anchor_xml)

    ### Step 2. Fetch the S/MIME signature for the trust anchor file from
    ### IANA using HTTPS. Get the signature file from its URL, write it to disk.
    try:
        signature_url = urlopen(URL_ROOT_ANCHORS_SIGNATURE)
    except Exception as this_exception:
        die("Was not able to open URL {}. returned text was '{}'.".format(\
            URL_ROOT_ANCHORS_SIGNATURE, this_exception))
    signature_contents = signature_url.read()
    signature_url.close()
    write_out_file(signature_filename, signature_contents)

    ### Step 3. Validate the signature on the trust anchor file using a
    ### built-in IANA CA key. Skip this step if using a local file.
    if opts.local:
        print("Not validating the local trust anchor file.")
    else:
        write_out_file(icann_ca_filename, ICANN_ROOT_CA_CERT)
        validate_detached_signature(trust_anchor_filename, signature_filename, icann_ca_filename)

    ### Step 4. Extract the trust anchor key digests from the trust anchor file
    trust_anchors = extract_trust_anchors_from_xml(trust_anchor_xml)

    ### Step 5. Check the validity period for each digest
    valid_trust_anchors = get_valid_trust_anchors(trust_anchors)

    ### Step 6. Verify that the trust anchors match the published KSKs
    ### file.
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

if __name__ == "__main__":
    main()
