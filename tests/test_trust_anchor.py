"""Tests for get_trust_anchor."""

import datetime
import os
import subprocess
import sys
from unittest import mock

import pytest

from get_trust_anchor.cli import (
    bytes_to_string,
    dnskey_to_hex_of_hash,
    extract_ksks_from_trust_anchors,
    extract_trust_anchors_from_xml,
    get_matching_ksk,
    get_valid_trust_anchors,
    export_ksk,
    write_out_file,
)


# --- bytes_to_string ---

class TestBytesToString:
    def test_pass_through_str(self):
        assert bytes_to_string("hello") == "hello"

    def test_bytes_decoded(self):
        assert bytes_to_string(b"hello") == "hello"

    def test_empty_string(self):
        assert bytes_to_string("") == ""

    def test_empty_bytes(self):
        assert bytes_to_string(b"") == ""


# --- dnskey_to_hex_of_hash ---

class TestDnskeyToHexOfHash:
    def test_sha256_ksk_2017(self, ksk_2017):
        result = dnskey_to_hex_of_hash(ksk_2017, "2")
        assert result == "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

    def test_sha256_ksk_2024(self, ksk_2024):
        result = dnskey_to_hex_of_hash(ksk_2024, "2")
        assert result == "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"

    def test_sha1_ksk_2017(self, ksk_2017):
        result = dnskey_to_hex_of_hash(ksk_2017, "1")
        # SHA-1 should produce a 40-char hex string
        assert len(result) == 40
        assert all(c in "0123456789ABCDEF" for c in result)

    def test_unknown_hash_type(self, ksk_2017):
        with pytest.raises(SystemExit):
            dnskey_to_hex_of_hash(ksk_2017, "99")


# --- extract_trust_anchors_from_xml ---

class TestExtractTrustAnchorsFromXml:
    def test_parses_all_digests(self, sample_xml):
        anchors = extract_trust_anchors_from_xml(sample_xml)
        assert len(anchors) == 3

    def test_required_fields_present(self, sample_xml):
        anchors = extract_trust_anchors_from_xml(sample_xml)
        for anchor in anchors:
            assert "KeyTag" in anchor
            assert "Algorithm" in anchor
            assert "DigestType" in anchor
            assert "Digest" in anchor
            assert "validFrom" in anchor
            assert "validUntil" in anchor

    def test_validity_dates(self, sample_xml):
        anchors = extract_trust_anchors_from_xml(sample_xml)
        # First anchor (KSK-2010) has both validFrom and validUntil
        assert anchors[0]["validFrom"] == "2010-07-15T00:00:00+00:00"
        assert anchors[0]["validUntil"] == "2019-01-11T00:00:00+00:00"
        # Second anchor (KSK-2017) has validFrom but no validUntil
        assert anchors[1]["validFrom"] == "2017-02-02T00:00:00+00:00"
        assert anchors[1]["validUntil"] == ""

    def test_digest_values(self, sample_xml):
        anchors = extract_trust_anchors_from_xml(sample_xml)
        assert anchors[0]["KeyTag"] == "19036"
        assert anchors[1]["KeyTag"] == "20326"
        assert anchors[2]["KeyTag"] == "38696"

    def test_optional_publickey_and_flags(self, sample_xml_with_publickey):
        anchors = extract_trust_anchors_from_xml(sample_xml_with_publickey)
        for anchor in anchors:
            assert "PublicKey" in anchor
            assert "Flags" in anchor
            assert anchor["Flags"] == "257"

    def test_xml_too_short(self):
        with pytest.raises(SystemExit):
            extract_trust_anchors_from_xml("short")

    def test_bytes_input(self, sample_xml):
        anchors = extract_trust_anchors_from_xml(sample_xml.encode("ascii"))
        assert len(anchors) == 3


# --- get_valid_trust_anchors ---

class TestGetValidTrustAnchors:
    def _make_anchor(self, valid_from, valid_until=""):
        return {
            "KeyTag": "12345", "Algorithm": "8", "DigestType": "2",
            "Digest": "AABB", "validFrom": valid_from, "validUntil": valid_until,
        }

    def test_current_anchor_passes(self):
        anchor = self._make_anchor("2020-01-01T00:00:00+00:00")
        result = get_valid_trust_anchors([anchor])
        assert len(result) == 1

    def test_expired_anchor_filtered(self):
        anchor = self._make_anchor("2010-01-01T00:00:00+00:00", "2015-01-01T00:00:00+00:00")
        with pytest.raises(SystemExit):
            get_valid_trust_anchors([anchor])

    def test_future_anchor_filtered(self):
        anchor = self._make_anchor("2099-01-01T00:00:00+00:00")
        with pytest.raises(SystemExit):
            get_valid_trust_anchors([anchor])

    def test_empty_valid_from_filtered(self):
        anchor = self._make_anchor("")
        with pytest.raises(SystemExit):
            get_valid_trust_anchors([anchor])

    def test_mix_of_valid_and_expired(self):
        expired = self._make_anchor("2010-01-01T00:00:00+00:00", "2015-01-01T00:00:00+00:00")
        current = self._make_anchor("2020-01-01T00:00:00+00:00")
        result = get_valid_trust_anchors([expired, current])
        assert len(result) == 1
        assert result[0] is current

    def test_anchor_with_valid_until_in_future(self):
        anchor = self._make_anchor("2020-01-01T00:00:00+00:00", "2099-12-31T00:00:00+00:00")
        result = get_valid_trust_anchors([anchor])
        assert len(result) == 1

    def test_real_fixture_filtering(self, sample_xml):
        anchors = extract_trust_anchors_from_xml(sample_xml)
        valid = get_valid_trust_anchors(anchors)
        # KSK-2010 (19036) is expired, KSK-2017 (20326) and KSK-2024 (38696) should be valid
        key_tags = [a["KeyTag"] for a in valid]
        assert "19036" not in key_tags
        assert "20326" in key_tags
        assert "38696" in key_tags


# --- extract_ksks_from_trust_anchors ---

class TestExtractKsksFromTrustAnchors:
    def test_extracts_ksks(self, sample_xml_with_publickey):
        anchors = extract_trust_anchors_from_xml(sample_xml_with_publickey)
        ksks = extract_ksks_from_trust_anchors(anchors)
        assert len(ksks) == 2
        for ksk in ksks:
            assert ksk["f"] == "257"
            assert ksk["p"] == 3
            assert ksk["a"] == "8"
            assert len(ksk["k"]) > 0

    def test_skips_anchors_without_publickey(self, sample_xml):
        anchors = extract_trust_anchors_from_xml(sample_xml)
        ksks = extract_ksks_from_trust_anchors(anchors)
        assert len(ksks) == 0


# --- get_matching_ksk ---

class TestGetMatchingKsk:
    def test_matching_ksk_found(self, ksk_2017):
        trust_anchor = {
            "DigestType": "2",
            "Digest": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        }
        result = get_matching_ksk([ksk_2017], [trust_anchor])
        assert len(result) == 1
        assert result[0] is ksk_2017

    def test_no_match_exits(self, ksk_2017):
        trust_anchor = {"DigestType": "2", "Digest": "0000000000000000"}
        with pytest.raises(SystemExit):
            get_matching_ksk([ksk_2017], [trust_anchor])

    def test_multiple_ksks(self, ksk_2017, ksk_2024):
        anchors = [
            {
                "DigestType": "2",
                "Digest": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
            },
            {
                "DigestType": "2",
                "Digest": "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
            },
        ]
        result = get_matching_ksk([ksk_2017, ksk_2024], anchors)
        assert len(result) == 2


# --- export_ksk ---

class TestExportKsk:
    def test_writes_dnskey_and_ds(self, tmp_dir, ksk_2017):
        export_ksk([ksk_2017], "ds.txt", "dnskey.txt")
        assert os.path.exists("dnskey.txt")
        assert os.path.exists("ds.txt")

        with open("dnskey.txt") as f:
            dnskey = f.read()
        assert dnskey.startswith(". IN DNSKEY 257 3 8 ")
        assert dnskey.strip().endswith("=")

        with open("ds.txt") as f:
            ds = f.read()
        assert ". IN DS 20326 8 2 " in ds

    def test_keytag_calculation(self, tmp_dir, ksk_2024):
        export_ksk([ksk_2024], "ds.txt", "dnskey.txt")
        with open("ds.txt") as f:
            ds = f.read()
        assert ". IN DS 38696 8 2 " in ds

    def test_multiple_ksks(self, tmp_dir, ksk_2017, ksk_2024):
        export_ksk([ksk_2017, ksk_2024], "ds.txt", "dnskey.txt")
        with open("dnskey.txt") as f:
            lines = f.read().strip().split("\n")
        assert len(lines) == 2
        with open("ds.txt") as f:
            lines = f.read().strip().split("\n")
        assert len(lines) == 2


# --- write_out_file ---

class TestWriteOutFile:
    def test_writes_string(self, tmp_dir):
        write_out_file("test.txt", "hello world")
        with open("test.txt") as f:
            assert f.read() == "hello world"

    def test_writes_bytes(self, tmp_dir):
        write_out_file("test.bin", b"\x00\x01\x02")
        with open("test.bin", "rb") as f:
            assert f.read() == b"\x00\x01\x02"

    def test_backup_existing(self, tmp_dir):
        write_out_file("test.txt", "first")
        write_out_file("test.txt", "second")
        with open("test.txt") as f:
            assert f.read() == "second"
        # A backup file should exist
        backups = [f for f in os.listdir(".") if f.startswith("test.txt.backup_")]
        assert len(backups) == 1


# --- CLI integration ---

class TestCLI:
    def test_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "get_trust_anchor", "--help"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "DNSSEC Trust Anchor Tool" in result.stdout

    def test_local_file_not_found(self, tmp_dir):
        result = subprocess.run(
            [sys.executable, "-m", "get_trust_anchor", "--local", "nonexistent.xml"],
            capture_output=True, text=True,
        )
        assert result.returncode != 0

    def test_local_with_ksks_from_trust_anchor(self, tmp_dir, sample_xml_with_publickey):
        xml_path = str(tmp_dir / "anchors.xml")
        sig_path = str(tmp_dir / "anchors.p7s")
        with open(xml_path, "w") as f:
            f.write(sample_xml_with_publickey)
        with open(sig_path, "wb") as f:
            f.write(b"\x00")  # dummy signature; validation is disabled
        result = subprocess.run(
            [sys.executable, "-m", "get_trust_anchor",
             "--local", xml_path,
             "--local-sig", sig_path,
             "--no-validation",
             "--ksks-from-trust-anchor"],
            capture_output=True, text=True,
            cwd=str(tmp_dir),
        )
        assert result.returncode == 0, result.stderr

        fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        with open(os.path.join(fixtures_dir, "ksk-as-dnskey.txt")) as f:
            expected_dnskey = f.read()
        with open(os.path.join(fixtures_dir, "ksk-as-ds.txt")) as f:
            expected_ds = f.read()

        with open(str(tmp_dir / "ksk-as-dnskey.txt")) as f:
            assert f.read() == expected_dnskey
        with open(str(tmp_dir / "ksk-as-ds.txt")) as f:
            assert f.read() == expected_ds
