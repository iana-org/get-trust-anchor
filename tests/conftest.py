import os
import pytest


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def sample_xml():
    """A minimal but realistic trust anchor XML document."""
    with open(os.path.join(FIXTURES_DIR, "root-anchors.xml")) as f:
        return f.read()


@pytest.fixture
def sample_xml_with_publickey():
    """Trust anchor XML that includes PublicKey and Flags elements."""
    with open(os.path.join(FIXTURES_DIR, "root-anchors-with-keys.xml")) as f:
        return f.read()


@pytest.fixture
def ksk_2017():
    """The KSK-2017 key as a DNSKEY dict."""
    return {
        'f': '257', 'p': '3', 'a': '8',
        'k': ('AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3'
              '+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv'
              'ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0'
              'jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZ'
              'G+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRU'
              'fhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1'
              'AkUTV74bU=')
    }


@pytest.fixture
def ksk_2024():
    """The KSK-2024 key as a DNSKEY dict."""
    return {
        'f': '257', 'p': '3', 'a': '8',
        'k': ('AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/c'
              'idltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbG'
              'iShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siF'
              'UiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdV'
              'wuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K'
              '+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeay'
              'ffKC73PYc=')
    }


@pytest.fixture
def tmp_dir(tmp_path):
    """Provide a temporary directory and chdir into it, restoring cwd after."""
    original = os.getcwd()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(original)
