"""Shared dataclass models used across security-related modules."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GNpublicKey:
    """Compressed EC public key with prefix metadata."""
    pk: bytes = b""
    prefix: str = ""


@dataclass
class GNpsidSsp:
    psid: Optional[int] = None
    bitmapSsp: Optional[str] = None


@dataclass
class GNecdsaNistP256:
    p256_x_only: bytes = b""
    p256_fill: bytes = b""
    p256_compressed_y_0: bytes = b""
    p256_compressed_y_1: bytes = b""
    p256_uncompressed_x: bytes = b""
    p256_uncompressed_y: bytes = b""


@dataclass
class GNtbsCertDC:
    id: int = 0
    name: str = ""
    cracaId: str = ""
    crlSeries: int = 0
    validityPeriod_start: int = 0
    validityPeriod_duration: int = 0
    appPermissions: List[GNpsidSsp] = field(default_factory=list)
    symAlgEnc: int = 0
    encPublicKey: GNecdsaNistP256 = field(default_factory=GNecdsaNistP256)
    verifyKeyIndicator: GNecdsaNistP256 = field(default_factory=GNecdsaNistP256)


@dataclass
class GNcertificateDC:
    version: int = 0
    type: int = 0
    issuer: str = ""
    tbs: GNtbsCertDC = field(default_factory=GNtbsCertDC)
    rSig: GNecdsaNistP256 = field(default_factory=GNecdsaNistP256)
    signature_sSig: str = ""


@dataclass
class GNsignMaterial:
    r: bytes = b""
    s: bytes = b""


@dataclass
class EncData:
    ciphertextWithTag: bytes = b""
    encryptedKey: bytes = b""
    ephemeralPublicKey: bytes = b""
    x_value: bytes = b""
    y_value: bytes = b""
    eciesTag: bytes = b""
    nonce: bytes = b""


@dataclass
class IniAT:
    recipientAA: str = ""
    aaCert1: str = ""
    aaCert2: str = ""
    aaCert3: str = ""
    aaCert4: str = ""
    bitmapCAM: str = ""
    bitmapDENM: str = ""
    eaIDstring: str = ""
    itsID: str = ""
    public_key_rfc: str = ""
    private_key_rfc1: str = ""
    private_key_rfc2: str = ""


@dataclass
class IniEC:
    eaCert1: str = "UNKNOWN"
    eaCert2: str = "UNKNOWN"
    eaCert3: str = "UNKNOWN"
    pk_rfc: str = "UNKNOWN"
    sk_rfc: str = "UNKNOWN"
    itsID: str = "UNKNOWN"
    recipientID: str = "UNKNOWN"
    bitmapSspEA: str = "UNKNOWN"


@dataclass
class tbsDataSigned:
    protocolversion: int = 0
    unsecuredData: str = ""
    header_psid: int = 0
    header_generationTime: int = 0


@dataclass
class eData:
    recipient: str = ""
    nonce: str = ""
    ciphertext: str = ""


@dataclass
class sData:
    hashID: int = 0
    tbsdata: tbsDataSigned = field(default_factory=tbsDataSigned)
    signer_digest: str = ""
    rSig: GNecdsaNistP256 = field(default_factory=GNecdsaNistP256)
    signature_sSig: str = ""


@dataclass
class contData:
    signData: sData = field(default_factory=sData)
    encrData: eData = field(default_factory=eData)
    unsecuredData: str = ""


@dataclass
class cPacket:
    m_protocolversion: int = 0
    content: contData = field(default_factory=contData)


@dataclass
class response:
    requestHash: str = ""
    response_code: int = 0
    certificate: GNcertificateDC = field(default_factory=GNcertificateDC)


__all__ = [
    "GNpublicKey",
    "GNpsidSsp",
    "GNecdsaNistP256",
    "GNtbsCertDC",
    "GNcertificateDC",
    "GNsignMaterial",
    "EncData",
    "IniAT",
    "IniEC",
    "tbsDataSigned",
    "eData",
    "sData",
    "contData",
    "cPacket",
    "response",
]
