"""Tests for get_trust_anchor."""

import datetime
import hashlib
import os
import subprocess
import sys

import pytest

from get_trust_anchor.cli import (
    ICANN_ROOT_CA_CERTS,
    ICANN_ROOT_CA_V2,
    bytes_to_string,
    dnskey_to_hex_of_hash,
    export_ksk,
    extract_ksks_from_trust_anchors,
    extract_trust_anchors_from_xml,
    format_records,
    get_matching_ksk,
    get_valid_trust_anchors,
    pem_bundle,
    validate_detached_signature,
    verification_options,
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
            "KeyTag": "12345",
            "Algorithm": "8",
            "DigestType": "2",
            "Digest": "AABB",
            "validFrom": valid_from,
            "validUntil": valid_until,
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
            assert len(str(ksk["k"])) > 0

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


# --- format_records ---


class TestFormatRecords:
    def test_returns_dnskey_and_ds(self, ksk_2017):
        dnskey, ds = format_records([ksk_2017])
        assert dnskey.startswith(". IN DNSKEY 257 3 8 ")
        assert ". IN DS 20326 8 2 " in ds

    def test_multiple_ksks(self, ksk_2017, ksk_2024):
        dnskey, ds = format_records([ksk_2017, ksk_2024])
        assert len(dnskey.strip().split("\n")) == 2
        assert len(ds.strip().split("\n")) == 2


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


# --- built-in ICANN CA certificates ---


class TestBuiltinCaCertificates:
    def test_matches_published_bundle(self):
        # Point-in-time check that the built-in ICANN CA certificates are the published
        # ones: the CA file the tool writes matches icannbundle.pem's entry in
        # https://data.iana.org/root-anchors/checksums-sha256.txt (2026-10-19).
        ca_file = pem_bundle(ICANN_ROOT_CA_CERTS).encode()
        assert (
            hashlib.sha256(ca_file).hexdigest()
            == "18ce7215812d1a2cad8d9d4d3d7c26f7235a9b5ec6f0c1e214e15230fd4f9e24"
        )


# --- validate_detached_signature ---

# A real root-anchors.xml/.p7s pair from data.iana.org, signed under ICANN Root CA. It is
# validated as of its capture date, so certificate expiry never breaks these tests.
SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "2026-10-19")
SAMPLE_XML = os.path.join(SAMPLE_DIR, "root-anchors.xml")
SAMPLE_P7S = os.path.join(SAMPLE_DIR, "root-anchors.p7s")
SAMPLE_TIME = datetime.datetime(2026, 10, 19, tzinfo=datetime.timezone.utc)


class TestValidateDetachedSignature:
    def _validate(self, tmp_path, certs, content=SAMPLE_XML, at_time=SAMPLE_TIME):
        ca_filename = str(tmp_path / "ca.pem")
        with open(ca_filename, "w") as f:
            f.write(pem_bundle(certs))
        validate_detached_signature(content, SAMPLE_P7S, ca_filename, at_time=at_time)

    def test_builtin_certs_validate_sample(self, tmp_path):
        self._validate(tmp_path, ICANN_ROOT_CA_CERTS)

    def test_tampered_content_rejected(self, tmp_path):
        tampered = str(tmp_path / "root-anchors.xml")
        with open(SAMPLE_XML, "rb") as f:
            xml = f.read()
        with open(tampered, "wb") as f:
            f.write(xml.replace(b"<KeyTag>20326<", b"<KeyTag>20327<"))
        with pytest.raises(SystemExit):
            self._validate(tmp_path, ICANN_ROOT_CA_CERTS, content=tampered)

    def test_v2_alone_rejects_v1_signed_sample(self, tmp_path):
        # The .p7s carries its own copy of ICANN Root CA; this shows that copy is not
        # trusted by itself, so the pass above came from the built-in certificates.
        with pytest.raises(SystemExit):
            self._validate(tmp_path, [ICANN_ROOT_CA_V2])

    def test_rejected_after_signer_expiry(self, tmp_path):
        # The signing certificate expires 2029-03-13, before ICANN Root CA (2029-12-18);
        # this shows at_time reaches openssl.
        with pytest.raises(SystemExit):
            self._validate(
                tmp_path,
                ICANN_ROOT_CA_CERTS,
                at_time=datetime.datetime(2029, 6, 1, tzinfo=datetime.timezone.utc),
            )


# --- system CA store ---

# The signature must chain to the ICANN CA certificates, not to any CA the system trusts.
# This is a root-anchors.xml (one KeyTag changed) signed under a throwaway test CA whose
# keys were discarded. CI adds the test CA to the system CA store and sets
# GET_TRUST_ANCHOR_TEST_CA_IN_SYSTEM_STORE=1 (see .github/workflows/test.yml).
SYSTEM_CA_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "system-ca")
SYSTEM_CA = os.path.join(SYSTEM_CA_DIR, "test-ca.pem")
SYSTEM_CA_XML = os.path.join(SYSTEM_CA_DIR, "root-anchors.xml")
SYSTEM_CA_P7S = os.path.join(SYSTEM_CA_DIR, "root-anchors.p7s")


class TestSystemCaStore:
    def test_sample_validates_against_its_ca(self):
        # Control: the sample's signature is valid when its CA is the CA file.
        validate_detached_signature(SYSTEM_CA_XML, SYSTEM_CA_P7S, SYSTEM_CA)

    @pytest.mark.skipif(
        os.environ.get("GET_TRUST_ANCHOR_TEST_CA_IN_SYSTEM_STORE") != "1",
        reason="needs the test CA in the system CA store (done in CI)",
    )
    def test_system_ca_store_not_trusted(self, tmp_path):
        ca_filename = str(tmp_path / "ca.pem")
        with open(ca_filename, "w") as f:
            f.write(pem_bundle(ICANN_ROOT_CA_CERTS))
        with pytest.raises(SystemExit):
            validate_detached_signature(SYSTEM_CA_XML, SYSTEM_CA_P7S, ca_filename)


class TestVerificationOptions:
    @pytest.mark.parametrize(
        ("version", "expected"),
        [
            # Version lines printed by openssl in CI or local testing.
            (
                "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)",
                ["-no-CApath", "-no-CAstore"],
            ),
            ("OpenSSL 1.1.1k  FIPS 25 Mar 2021", ["-no-CApath"]),
            ("LibreSSL 4.3.1", ["-CApath", "/empty"]),
            ("LibreSSL 3.3.6", ["-CApath", "/empty"]),
        ],
    )
    def test_supported(self, version, expected):
        assert verification_options(version, lambda: "/empty") == expected

    @pytest.mark.parametrize("version", ["OpenSSL 1.0.2k-fips  26 Jan 2017", "BoringSSL", ""])
    def test_unsupported(self, version):
        with pytest.raises(ValueError):
            verification_options(version, lambda: "/empty")


class TestSystemTrustOptions:
    def _validate(self, tmp_path, monkeypatch, system_trust_options):
        monkeypatch.setattr("get_trust_anchor.cli.openssl_version", lambda: "BoringSSL")
        ca_filename = str(tmp_path / "ca.pem")
        with open(ca_filename, "w") as f:
            f.write(pem_bundle(ICANN_ROOT_CA_CERTS))
        validate_detached_signature(
            SAMPLE_XML,
            SAMPLE_P7S,
            ca_filename,
            at_time=SAMPLE_TIME,
            system_trust_options=system_trust_options,
        )

    def test_unsupported_openssl_refused(self, tmp_path, monkeypatch, capsys):
        with pytest.raises(SystemExit):
            self._validate(tmp_path, monkeypatch, None)
        assert "--system-trust-options" in capsys.readouterr().err

    def test_options_replace_the_chosen_ones(self, tmp_path, monkeypatch, capsys):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        self._validate(tmp_path, monkeypatch, ["-CApath", str(empty_dir)])
        err = capsys.readouterr().err
        assert f"WARNING: using BoringSSL with --system-trust-options (-CApath {empty_dir})" in err
        assert "Validation of the signature over the file succeeded." in err

    def test_unrecognised_option_fails(self, tmp_path, monkeypatch):
        # OpenSSL 3.0.13 and 1.1.1k exit 0 on an option they do not recognise, without
        # verifying; this must still fail.
        with pytest.raises(SystemExit):
            self._validate(tmp_path, monkeypatch, ["-no-such-option"])


# --- CLI integration ---


class TestCLI:
    def test_help(self):
        result = subprocess.run(
            [sys.executable, "-m", "get_trust_anchor", "--help"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "DNSSEC Trust Anchor Tool" in result.stdout

    def test_local_file_not_found(self, tmp_dir):
        result = subprocess.run(
            [sys.executable, "-m", "get_trust_anchor", "--local", "nonexistent.xml"],
            capture_output=True,
            text=True,
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
            [
                sys.executable,
                "-m",
                "get_trust_anchor",
                "--local",
                xml_path,
                "--local-sig",
                sig_path,
                "--no-validation",
                "--ksks-from-trust-anchor",
            ],
            capture_output=True,
            text=True,
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

    def _run_local(self, tmp_dir, sample_xml_with_publickey, extra_args):
        """Helper to run with local fixtures and extra CLI args."""
        xml_path = str(tmp_dir / "anchors.xml")
        sig_path = str(tmp_dir / "anchors.p7s")
        with open(xml_path, "w") as f:
            f.write(sample_xml_with_publickey)
        with open(sig_path, "wb") as f:
            f.write(b"\x00")
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "get_trust_anchor",
                "--local",
                xml_path,
                "--local-sig",
                sig_path,
                "--no-validation",
                "--ksks-from-trust-anchor",
                *extra_args,
            ],
            capture_output=True,
            text=True,
            cwd=str(tmp_dir),
        )

    def test_print_dnskey(self, tmp_dir, sample_xml_with_publickey):
        result = self._run_local(tmp_dir, sample_xml_with_publickey, ["--print-dnskey"])
        assert result.returncode == 0, result.stderr
        assert ". IN DNSKEY 257 3 8 " in result.stdout
        assert ". IN DS " not in result.stdout
        # Should not write files when printing to stdout
        assert not (tmp_dir / "ksk-as-dnskey.txt").exists()
        assert not (tmp_dir / "ksk-as-ds.txt").exists()

    def test_print_ds(self, tmp_dir, sample_xml_with_publickey):
        result = self._run_local(tmp_dir, sample_xml_with_publickey, ["--print-ds"])
        assert result.returncode == 0, result.stderr
        assert ". IN DS " in result.stdout
        assert ". IN DNSKEY " not in result.stdout
        assert not (tmp_dir / "ksk-as-dnskey.txt").exists()

    def test_print_both(self, tmp_dir, sample_xml_with_publickey):
        result = self._run_local(
            tmp_dir, sample_xml_with_publickey, ["--print-dnskey", "--print-ds"]
        )
        assert result.returncode == 0, result.stderr
        assert ". IN DNSKEY 257 3 8 " in result.stdout
        assert ". IN DS " in result.stdout

    def test_print_dnskey_matches_fixture(self, tmp_dir, sample_xml_with_publickey):
        result = self._run_local(tmp_dir, sample_xml_with_publickey, ["--print-dnskey"])
        fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
        with open(os.path.join(fixtures_dir, "ksk-as-dnskey.txt")) as f:
            assert result.stdout == f.read()

    def test_status_messages_on_stderr(self, tmp_dir, sample_xml_with_publickey):
        result = self._run_local(tmp_dir, sample_xml_with_publickey, ["--print-ds"])
        assert result.returncode == 0
        # Status messages should be on stderr, not stdout
        assert "KeyDigest" in result.stderr
        # stdout should only contain DS records
        for line in result.stdout.strip().split("\n"):
            assert line.startswith(". IN DS ")
