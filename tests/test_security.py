import json
import pytest

from replay.utils.Security import Security


CERT_PATH = "PKIManager/certificates/certificates.json"


def load_certificates():
    with open(CERT_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def test_create_secure_packet_raises_when_mtype_not_cam():
    security = Security()
    certificates = load_certificates()

    unsecured_payload = b"test payload"

    with pytest.raises(KeyError) as excinfo:
        security.createSecurePacket(
            unsecured_payload,
            certificates,
            vehicle_id=0,
            isCertificate=True,
            mType="DENM",
        )

    assert "headerInfo" in str(excinfo.value)
