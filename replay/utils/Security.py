import os
import hashlib
import asn1tools
import sys
import glob
import json
import time

from dataclasses import dataclass, field
from typing import List
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key, load_der_public_key,
    load_pem_private_key, load_der_private_key,
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature, Prehashed

@dataclass
class GNpublicKey:
    """
    Replica 1:1 dell'oggetto di ritorno usato in C++ per esporre
    la chiave pubblica in forma compressa *senza prefisso* e il tipo di prefisso.
    - x_only: stringa esadecimale (32 byte) dell'ascissa X
    - prefix_type: 2 se y è pari (0x02), 3 se y è dispari (0x03)
    """
    pk: bytes = b""
    prefix: str = ""  # 2 (y pari) oppure 3 (y dispari)

@dataclass
class GNpsidSsp:
    psid: int = None
    bitmapSsp: str = None

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
    tbsdata: "tbsDataSigned" = field(default_factory=lambda: tbsDataSigned())
    signer_digest: str = ""
    rSig: GNecdsaNistP256 = field(default_factory=GNecdsaNistP256)
    signature_sSig: str = ""

@dataclass
class contData:
    signData: "sData" = field(default_factory=lambda: sData())
    encrData: "eData" = field(default_factory=lambda: eData())
    unsecuredData: str = ""

@dataclass
class cPacket:
    m_protocolversion: int = 0
    content: "contData" = field(default_factory=lambda: contData())

@dataclass
class response:
    requestHash: str = ""
    response_code: int = 0
    certificate: GNcertificateDC = field(default_factory=GNcertificateDC)  # Fix: era GNecdsaNistP256


class Security():
    def __init__(self):
        self.m_protocolVersion = 3
        self.m_hashId = 'sha256'
        self.m_generationTime = None
        self.m_digest = None
        self.m_psid = None
        self.ASN1Module = None
        self.CURVE = ec.SECP256R1()
        self.ec_key = None

        self.path = os.path.abspath(os.path.dirname(__file__))
        self.project_root = os.path.abspath(os.path.join(self.path, os.pardir, os.pardir))

    @staticmethod
    def print_error(error: Exception) -> None:
        print(error, file=sys.stderr)


    @staticmethod
    def computeSHA256(data: bytes) -> bytes:
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.digest()
    
    def loadECKeyFromFile(self, private_key_file: str, public_key_file: str, password: bytes | None = None):
        try:
            with open(private_key_file, 'rb') as f:
                priv_file = f.read()
        except Exception as e:
            print("Error opening file to load private key", file=sys.stderr)
            self.print_error(e)
            return None
        ec_key = None
        try:
            ec_key = load_pem_private_key(priv_file, password=password)
        except Exception as e:
            print("Error reading private key from file", file=sys.stderr)
            self.print_error(e)
            return None
        if not isinstance(ec_key, ec.EllipticCurvePrivateKey):
            print("Loaded private key is not an EC key", file=sys.stderr)
            return None
        try:
            with open(public_key_file, 'rb') as f:
                pub_bytes = f.read()
        except Exception as e:
            print("Error opening file to load public key", file=sys.stderr)
            self.print_error(e)
            return None
        try:
            pub_key = load_pem_public_key(pub_bytes)
        except Exception as e:
            print("Error reading public key from file", file=sys.stderr)
            self.print_error(e)
            return None
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            print("Loaded public key is not an EC key", file=sys.stderr)
            return None

        if not isinstance(ec_key.curve, type(self.CURVE)) or not isinstance(pub_key.curve, type(self.CURVE)):
            print("EC curve mismatch or unsupported curve", file=sys.stderr)
            return None
        
        priv_pub_numbers = ec_key.public_key().public_numbers()
        loaded_pub_numbers = pub_key.public_numbers()
        if (priv_pub_numbers.x != loaded_pub_numbers.x) or (priv_pub_numbers.y != loaded_pub_numbers.y):
            print("Public key does not match the private key", file=sys.stderr)
            return None
        return ec_key

    def encodeASN1(self, asn1_type: str, data: dict) -> bytes:
        if not self.ASN1Module:
            path = os.path.join(self.project_root, 'data', 'asn', 'security')
            files = glob.glob(f"{path}/*.asn")
            self.ASN1Module = asn1tools.compile_files(files, 'oer')
        encoded = self.ASN1Module.encode(asn1_type, data)
        return encoded
    
    def decodeASN1(self, asn1_type: str, data: bytes) -> dict:
        if not self.ASN1Module:
            path = os.path.join(self.project_root, 'data', 'asn', 'security')
            files = glob.glob(f"{path}/*.asn")
            self.ASN1Module = asn1tools.compile_files(files, 'oer')
        decoded = self.ASN1Module.decode(asn1_type, data)
        return decoded
    
    def reconverECKeyPair(self, vehicle_id: int) -> GNpublicKey:
        ec_key = None
        try:
            # TODO sistemare il percorso per fare in modo che punti ai file giusti
            keys_folder = os.path.join(
                self.project_root,
                'PKIManager',
                'certificates',
                'keys',
                f'ITS_{vehicle_id}'
            )
            private_key_file = os.path.join(keys_folder, 'ephSKEY2.pem')
            public_key_file = os.path.join(keys_folder, 'ephPKEY2.pem')
            ec_key = self.loadECKeyFromFile(private_key_file, public_key_file)
            if ec_key is None:
                return GNpublicKey()  # Empty instance
            self.ec_key = ec_key
            pub_key = ec_key.public_key()

            compressed_bytes = pub_key.public_bytes(
                encoding=Encoding.X962,
                format=PublicFormat.CompressedPoint
            )
            prefix_byte = compressed_bytes[0]
            if prefix_byte == 0x02:
                prefix_type = "compressed_y_0"
            elif prefix_byte == 0x03:
                prefix_type = "compressed_y_1"
            
            result_key = GNpublicKey(
                pk = compressed_bytes[1:],
                prefix = prefix_type
            )
            return result_key
        except Exception as e:
            print(f"Error in reconverECKeyPair: {e}")
            return GNpublicKey()  # Empty instance
    
    def signHash(self, hash: bytes, ec_private_key: ec.EllipticCurvePrivateKey) -> dict | None:

        try:
            # Controlli di input
            if not isinstance(hash, (bytes, bytearray)):
                raise TypeError("hash_bytes deve essere bytes")
            if len(hash) != 32:
                raise ValueError("SHA-256 digest atteso: 32 byte")
            
            signature = ec_private_key.sign(hash,ec.ECDSA(Prehashed(hashes.SHA256())))
            return signature
        except Exception as e:
            print("Error signing hash", file=sys.stderr)
    
    def signatureCreation(self, tbsData: bytes, certificate: bytes, vehicle_id: int) -> GNsignMaterial:
        
        tbsData_hash = self.computeSHA256(tbsData)
        certificate_hash = self.computeSHA256(certificate)
        concatenated = tbsData_hash + certificate_hash
        final_hash = self.computeSHA256(concatenated)
        self.reconverECKeyPair(vehicle_id)

        signature = self.signHash(final_hash, self.ec_key)
        if signature is None:
            return GNsignMaterial()
        
        r, s = decode_dss_signature(signature)
        r_bytes = r.to_bytes(32, byteorder='big')
        s_bytes = s.to_bytes(32, byteorder='big')

        return GNsignMaterial(r=r_bytes, s=s_bytes)

    @staticmethod
    def getCurrentTimestamp() -> int:
        # microsecondi dall'epoch UNIX corrente
        microseconds_since_epoch = time.time_ns() // 1000

        seconds_per_year = 365 * 24 * 60 * 60
        leap_seconds = 8 * 24 * 60 * 60
        epoch_difference_seconds = (34 * seconds_per_year) + leap_seconds
        epoch_difference = epoch_difference_seconds * 1_000_000

        return (microseconds_since_epoch - epoch_difference)
    @staticmethod
    def getKeyFromCertificate(certificate_info: dict) -> tuple[str | None, bytes | None]:
        try:
            # Se il certificato ha la struttura con 'tbs' e 'verifyKeyIndicator'
            if "tbs" in certificate_info and "verifyKeyIndicator" in certificate_info["tbs"]:
                key_dict = certificate_info["tbs"]["verifyKeyIndicator"]
            else:
                # Altrimenti assume che certificate_info sia già il dict delle chiavi
                key_dict = certificate_info

            for field in [
                "p256_x_only",
                "p256_fill",
                "p256_compressed_y_0",
                "p256_compressed_y_1",
                "p256_uncompressed_x",
                "p256_uncompressed_y"
            ]:
                value = key_dict.get(field, "")
                if isinstance(value, str) and value:
                    return field, bytes.fromhex(value)
            return None, None
        except Exception as e:
            print(f"Error in getKeyFromCertificate: {e}")
            return None, None

    def createSecurePacket(self, UnsecuredData: bytes, certificates: dict, vehicle_id: int , isCertificate: bool, mType: str) -> cPacket:
        
        try:
            vehicle_cert = certificates[str(vehicle_id)]['AT']
        except KeyError as exc:
            raise KeyError(f"Missing AT certificate for vehicle {vehicle_id}") from exc

        certficate_info = vehicle_cert['certificate']
        certificate_raw_hex = vehicle_cert['certificateRaw']
        
        ieeeData = {}
        ieeeData['protocolVersion'] = self.m_protocolVersion
        ieeeContent = ('signedData', {})
        ieeeContent[1]['hashId'] = self.m_hashId

        tbs = {}
        signPayload = {}
        dataPayload = {}
        dataPayload['protocolVersion'] = self.m_protocolVersion
        dataContentPayload = ('unsecuredData', UnsecuredData)
        dataPayload['content'] = dataContentPayload
        signPayload['data'] = dataPayload
        tbs['payload'] = signPayload

        if mType == 'CAM':
            tbs['headerInfo'] = {}
            tbs['headerInfo']['psid'] = 36
    
        m_generationTime = self.getCurrentTimestamp()
        tbs['headerInfo']['generationTime'] = m_generationTime
        ieeeContent[1]['tbsData'] = tbs

        certificate_raw = bytes.fromhex(certificate_raw_hex)
        certificate_decoded = self.decodeASN1('Certificate', certificate_raw)

        if isCertificate:
            ieeeContent[1]['signer'] = ('certificate', [])
            ieeeContent[1]['signer'][1].append(certificate_decoded)
        else:
            certHash = self.computeSHA256(certificate_raw)
            ieeeContent[1]['signer'] = ('digest', certHash)
        
        tbs_encoded = self.encodeASN1('ToBeSignedData', tbs)
        sign_material = self.signatureCreation(tbs_encoded, certificate_raw, vehicle_id)
        signatureContent = ('ecdsaNistP256Signature', {
            'rSig': ('x-only', sign_material.r),
            'sSig': sign_material.s
        })
        ieeeContent[1]['signature'] = signatureContent
        ieeeData['content'] = ieeeContent
        encoded = self.encodeASN1('Ieee1609Dot2Data', ieeeData)
        return encoded

if __name__ == "__main__":
    dummy_bytes = b"Hello, World!"
    certificates = '/Users/giuseppe/Desktop/TRACENX/TRACEN-X/PKIManager/certificates/certificates.json'
    import json
    with open(certificates, 'r') as f:
        certificates = json.load(f)
    sec = Security()
    encoded0 = sec.createSecurePacket(dummy_bytes, certificates, 0, False, 'CAM')
    encoded1 = sec.createSecurePacket(dummy_bytes, certificates, 1, False, 'CAM')

    print(encoded0==encoded1)




            

            
            





