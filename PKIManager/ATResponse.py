import os
import hashlib
import asn1tools
import sys
import glob
import json

from dataclasses import dataclass, field, asdict, is_dataclass
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


from .INIReader import INIReader
from .CRReader import CRRReader



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


class ATResponse:
    def __init__(self):
        self.NONCE_LENGTH = 12
        self.AES_KEY_LENGTH = 16 # AES-128
        self.AES_CCM_TAG_LENGTH = 16
        self.HMAC_TAG_LENGTH = 32
        self.CURVE = ec.SECP256R1()  # NIST P-256

        self.path = os.path.abspath(os.path.dirname(__file__))

        self.dataResponse = None
        self.length = 0

        self.ephemeral = False
        self.m_ecKey = None
        self.m_EPHKey = None
        self.m_aesKeys = {}

    @staticmethod
    def _to_serializable(value):
        if is_dataclass(value):
            value = asdict(value)
        if isinstance(value, dict):
            return {key: ATResponse._to_serializable(val) for key, val in value.items()}
        if isinstance(value, list):
            return [ATResponse._to_serializable(item) for item in value]
        if isinstance(value, bytes):
            return value.hex()
        return value

    @staticmethod
    def retrieveStringFromFile(file_name):
        key = ""
        try:
            with open(file_name, "rb") as file_in:
                length_bytes = file_in.read(8)  # size_t is typically 8 bytes
                if len(length_bytes) < 8:
                    print("Error reading length from file.")
                    return key
                length = int.from_bytes(length_bytes, byteorder="little")
                key_bytes = file_in.read(length)
                key = key_bytes.decode("utf-8")
                print(f"Pre Shared Key retrieved: {key}")
        except Exception as e:
            print(f"Error opening file for reading: {e}")
        return key
    
    @staticmethod
    def saveStringToFile(key: str, file_name: str):
        try:
            dir_path = os.path.dirname(file_name)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            with open(file_name, "wb") as file_out:
                length = len(key)
                file_out.write(length.to_bytes(8, byteorder="little"))  # Scrivi la lunghezza (size_t, 8 byte)
                file_out.write(key.encode("utf-8"))  # Scrivi la stringa
                print("Pre Shared Key saved to binary file.")
        except Exception as e:
            print(f"Error opening file for writing: {e}")

    def readFileContent(self, filename):
        try:
            with open(filename, 'rb') as file:
                self.dataResponse = file.read()
                self.length = len(self.dataResponse)
        except Exception as e:
            print(f"Error reading file content: {e}")
            return None, 0
    
    def loadCompressedPublicKey(self, compressed_key: bytes, compression: int):
        
        if len(compressed_key) != 32:
            print("Key must be 32 bytes long")
            return None
        # Prefisso: 0x02 (y pari) o 0x03 (y dispari)
        if compression == 2:
            pk_data = b'\x02'
        elif compression == 3:
            pk_data = b'\x03'
        else:
            print("Compression must be 2 or 3")
            return None

        pk_data = pk_data + compressed_key
        if len(pk_data) != 33:
            print("La chiave compressa con prefisso non ha la lunghezza corretta (33 byte).")
            return None
        # Carica la chiave pubblica ECC da bytes compressi
        try:
            evp_pkey = ec.EllipticCurvePublicKey.from_encoded_point(self.CURVE, pk_data)            
            return evp_pkey
        
        except Exception as e:
            print(f"Errore nella conversione della chiave pubblica compressa: {e}")
            return None
    
    @staticmethod
    def computeSHA256(data: bytes) -> bytes:
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.digest()
    
    def decryptMessage(self, ciphertext_with_tag: bytes, nonce: bytes,
                    presharedKey: bytes) -> bytes:
        
        if presharedKey is None or len(presharedKey) != self.AES_KEY_LENGTH:
            raise ValueError(f"Pre-shared key must be {self.AES_KEY_LENGTH} bytes long")
        if nonce is None or len(nonce) != self.NONCE_LENGTH:
            raise ValueError(f"Nonce must be {self.NONCE_LENGTH} bytes long")

        aesKey = presharedKey 
        aesccm = AESCCM(aesKey, tag_length=self.AES_CCM_TAG_LENGTH)
        
        decryptedMessage = aesccm.decrypt(nonce, ciphertext_with_tag, None)
        return decryptedMessage
    
    def doDecryption(self, ciphertextWithTag: bytes, nonce: bytes, vehicle_id: int) -> bytes:

        cached_key = self.m_aesKeys.get(vehicle_id)
        if not cached_key:
            key_path = os.path.join(
                self.path,
                'certificates',
                'keys',
                f'ITS_{vehicle_id}',
                'pskAT.bin'
            )
            cached_key = self.retrieveStringFromFile(key_path)
            if not cached_key:
                raise ValueError("Failed to retrieve pre-shared key from file")
            self.m_aesKeys[vehicle_id] = cached_key

        psk = bytes.fromhex(cached_key)

        decrypted_message = self.decryptMessage(ciphertextWithTag, nonce, psk)
        
        return decrypted_message


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
    
    def readIniFile(self, vehicle_id: int) -> "IniAT":
        """Load AT configuration together with vehicle specific credentials."""
        ini_path = os.path.join(self.path, 'certificates', 'PKI_info.ini')
        reader = INIReader(ini_path)
        if reader.ParseError() < 0:
            print(f"[ERR] Can't load '{ini_path}'")

        ini = IniAT(
            aaCert1=reader.Get("ATinfo", "AAcert1", "UNKNOWN"),
            aaCert2=reader.Get("ATinfo", "AAcert2", "UNKNOWN"),
            aaCert3=reader.Get("ATinfo", "AAcert3", "UNKNOWN"),
            aaCert4=reader.Get("ATinfo", "AAcert4", "UNKNOWN"),
            recipientAA=reader.Get("ATinfo", "recipientAA", "UNKNOWN"),
            bitmapCAM=reader.Get("ATinfo", "bitmapCAM", "UNKNOWN"),
            bitmapDENM=reader.Get("ATinfo", "bitmapDENM", "UNKNOWN"),
            eaIDstring=reader.Get("ATinfo", "eaIDstring", "UNKNOWN"),
            public_key_rfc=reader.Get("ATinfo", "public_key_rfc", "UNKNOWN"),
            private_key_rfc1=reader.Get("ATinfo", "private_key_rfc1", "UNKNOWN"),
            private_key_rfc2=reader.Get("ATinfo", "private_key_rfc2", "UNKNOWN"),
        )

        credentials_path = os.path.join(self.path, 'certificates', 'credentials.json')
        credentials = CRRReader(credentials_path, vehicle_id)
        if credentials is None:
            print(f"[ERR] Can't load credentials for vehicle '{vehicle_id}'")
        else:
            ini.itsID = credentials.get('itsID', "UNKNOWN")
            ini.public_key_rfc = credentials.get('public_key_rfc', ini.public_key_rfc)
            private_key_full = credentials.get('private_key_rfc', "")
            if private_key_full:
                ini.private_key_rfc1 = private_key_full
                ini.private_key_rfc2 = ""

        return ini

    def loadECKeyFromRFC5480(self, private_key_rfc: str, public_key_rfc: str, password: bytes | None = None):

        try:
            priv_der = bytes.fromhex(private_key_rfc)
        except Exception as e:
            print("Error parsing private key hex string to DER", file=sys.stderr)
            return None
        try:
            pub_der = bytes.fromhex(public_key_rfc)
        except Exception as e:
            print("Error parsing public key hex string to DER", file=sys.stderr)
            return None
        try:
            priv_key = load_der_private_key(priv_der, password=password)
        except Exception as e:
            print("Error loading private key from PKCS#8 DER", file=sys.stderr)
            return None
        if not isinstance(priv_key, ec.EllipticCurvePrivateKey):
            print("Loaded private key is not an EC key", file=sys.stderr)
            return None
        try:
            pub_key = load_der_public_key(pub_der)
        except Exception as e:
            print("Error loading public key from RFC 5480 DER", file=sys.stderr)
            return None
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            print("Loaded public key is not an EC key", file=sys.stderr)
            return None

        if not isinstance(priv_key.curve, type(self.CURVE)) or not isinstance(pub_key.curve, type(self.CURVE)):
            print("EC curve mismatch or unsupported curve", file=sys.stderr)
            return None

        priv_pub_numbers = priv_key.public_key().public_numbers()
        loaded_pub_numbers = pub_key.public_numbers()
        if (priv_pub_numbers.x != loaded_pub_numbers.x) or (priv_pub_numbers.y != loaded_pub_numbers.y):
            print("Public key does not match the private key", file=sys.stderr)
            return None

        return priv_key
    
    def reconverECKeyPair(self, ephemeral: bool, vehicle_id: int, ini_data: IniAT | None = None) -> GNpublicKey:
        ec_key = None
        try:
            if ephemeral:
                keys_folder = os.path.join(self.path, 'certificates', 'keys', f'ITS_{vehicle_id}')
                private_key_file = os.path.join(keys_folder, 'ephSKEY.pem')
                public_key_file = os.path.join(keys_folder, 'ephPKEY.pem')
                ec_key = self.loadECKeyFromFile(private_key_file, public_key_file)
                if ec_key is None:
                    return GNpublicKey()  # Empty instance
                self.m_EPHecKey = ec_key

            else:
                if ini_data is None:
                    ini_data = self.readIniFile(vehicle_id)

                public_key_rfc = ini_data.public_key_rfc or ""
                private_key_rfc = (ini_data.private_key_rfc1 or "") + (ini_data.private_key_rfc2 or "")
                ec_key = self.loadECKeyFromRFC5480(private_key_rfc, public_key_rfc)
                
                if ec_key is None:
                    return GNpublicKey()  # Empty instance
                self.m_ecKey = ec_key
            
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

    def signatureVerification(self, tbsData: bytes, rValue: GNecdsaNistP256, sValue: str, verifyKeyIndicator: GNecdsaNistP256, ini: IniAT) -> bool:

        # Selezione della chiave pubblica dell'EA: preferisci forme utilizzabili (compressed/uncompressed)
        EAPublicKey = None
        if verifyKeyIndicator.p256_compressed_y_0:
            EAPublicKey = self.loadCompressedPublicKey(verifyKeyIndicator.p256_compressed_y_0, 2)
        elif verifyKeyIndicator.p256_compressed_y_1:
            EAPublicKey = self.loadCompressedPublicKey(verifyKeyIndicator.p256_compressed_y_1, 3)

        elif verifyKeyIndicator.p256_x_only:
            # x-only non è sufficiente per ricostruire la chiave pubblica (manca la parità di y)
            print("verifyKeyIndicator contiene solo x-only: impossibile ricostruire la chiave pubblica per la verifica.")
            return False
        else:
            print("verifyKeyIndicator non contiene una chiave pubblica utilizzabile.")
            return False

        if EAPublicKey is None:
            print("Failed to load the public key!")
            return False        

        signID = bytes.fromhex(ini.aaCert1 + ini.aaCert2 + ini.aaCert3 + ini.aaCert4)
        # Compute SHA-256 hashes
        tbsData_hash = self.computeSHA256(tbsData)
        signID_hash = self.computeSHA256(signID)
        # Concatenate hashes
        concatenatedHashes = tbsData_hash + signID_hash
        # Compute SHA-256 hash of the concatenated hashes
        final_hash = self.computeSHA256(concatenatedHashes)

        if rValue.p256_x_only:
            r = rValue.p256_x_only
        elif rValue.p256_compressed_y_0:
            r = rValue.p256_compressed_y_0
        elif rValue.p256_compressed_y_1:
            r = rValue.p256_compressed_y_1

        s = sValue

        # Convert bytes to integers
        r_int = int.from_bytes(r, byteorder='big')
        s_int = int.from_bytes(s, byteorder='big')
        # Riduzione di r modulo n (curva P-256) se necessario
        n = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
        if r_int >= n:
            r_int -= n
        # Create signature in DER format
        signature = encode_dss_signature(r_int, s_int)
        # Verify signature
        try:
            EAPublicKey.verify(
                signature,
                final_hash,
                ec.ECDSA(Prehashed(hashes.SHA256()))
            )
            return True
        except Exception as e:
            print("AT Signature is invalid")
            return False
    
    def getATResponse(self, vehicle_id: int):

        asn_folder = os.path.join("data", "asn", "security")
        asn_files = glob.glob(os.path.join(asn_folder, "*.asn"))
        asn1_modules = asn1tools.compile_files(asn_files, 'oer')

        ini = self.readIniFile(vehicle_id)
        binaryCert = bytes.fromhex(ini.aaCert1 + ini.aaCert2 + ini.aaCert3 + ini.aaCert4)

        certificate_hash = self.computeSHA256(binaryCert)
        certContent = binaryCert

        certData_decoded = asn1_modules.decode('CertificateBase', certContent)

        newCert = GNcertificateDC()
        newCert.version = certData_decoded['version']
        newCert.type = certData_decoded['type']
        _, newCert.issuer = certData_decoded['issuer']

        if certData_decoded['toBeSigned']['id'][0] == 'none':
            newCert.tbs.id = 0
        else:
            newCert.tbs.name = certData_decoded['toBeSigned']['id'][1]
        newCert.tbs.cracaId = certData_decoded['toBeSigned']['cracaId']
        newCert.tbs.crlSeries = certData_decoded['toBeSigned']['crlSeries']
        newCert.tbs.validityPeriod_start = certData_decoded['toBeSigned']['validityPeriod']['start']
        if certData_decoded['toBeSigned']['validityPeriod']['duration'][0] == 'hours':
            newCert.tbs.validityPeriod_duration = certData_decoded['toBeSigned']['validityPeriod']['duration'][1]
        
        for perm in certData_decoded['toBeSigned']['appPermissions']:
            newServ = GNpsidSsp()
            newServ.psid = perm['psid']
            if perm['ssp'][0] == 'bitmapSsp':
                newServ.bitmapSsp = perm['ssp'][1]
            newCert.tbs.appPermissions.append(newServ)
        
        newCert.tbs.symAlgEnc = certData_decoded['toBeSigned']['encryptionKey']['supportedSymmAlg']

        if certData_decoded['toBeSigned']['encryptionKey']['publicKey'][0] == 'eciesNistP256':
            switcher = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][0]
            if switcher == 'x-only':
                newCert.tbs.encPublicKey.p256_x_only = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
            elif switcher == 'fill':
                newCert.tbs.encPublicKey.p256_fill = None
            elif switcher == 'compressed-y-0':
                newCert.tbs.encPublicKey.p256_compressed_y_0 = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
            elif switcher == 'compressed-y-1':
                newCert.tbs.encPublicKey.p256_compressed_y_1 = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
            elif switcher == 'uncompressed':
                newCert.tbs.encPublicKey.p256_uncompressed_x = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
                newCert.tbs.encPublicKey.p256_uncompressed_y = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][2]
        
        # Filling last certificate field, verifyKeyIndicator.

        if certData_decoded['toBeSigned']['verifyKeyIndicator'][0] == 'verificationKey':
            if certData_decoded['toBeSigned']['verifyKeyIndicator'][1][0] == 'ecdsaNistP256':
                switcher = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][0]
                if switcher == 'x-only':
                    newCert.tbs.verifyKeyIndicator.p256_x_only = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                elif switcher == 'fill':
                    newCert.tbs.verifyKeyIndicator.p256_fill = None
                elif switcher == 'compressed-y-0':
                    newCert.tbs.verifyKeyIndicator.p256_compressed_y_0 = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                elif switcher == 'compressed-y-1':
                    newCert.tbs.verifyKeyIndicator.p256_compressed_y_1 = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                elif switcher == 'uncompressed':
                    newCert.tbs.verifyKeyIndicator.p256_uncompressed_x = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                    newCert.tbs.verifyKeyIndicator.p256_uncompressed_y = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][2]
        
        signcertData_decoded = certData_decoded['signature']
        present = signcertData_decoded[0]

        if present == 'ecdsaNistP256':
            switcher = signcertData_decoded[1]['rSig'][0]
            if switcher == 'x-only':
                newCert.rSig.p256_x_only = signcertData_decoded[1]['rSig'][1]
            elif switcher == 'fill':
                newCert.rSig.p256_fill = None
            elif switcher == 'compressed-y-0':
                newCert.rSig.p256_compressed_y_0 = signcertData_decoded[1]['rSig'][1]
            elif switcher == 'compressed-y-1':
                newCert.rSig.p256_compressed_y_1 = signcertData_decoded[1]['rSig'][1]
            elif switcher == 'uncompressed':
                newCert.rSig.p256_uncompressed_x = signcertData_decoded[1]['rSig'][1]
                newCert.rSig.p256_uncompressed_y = signcertData_decoded[1]['rSig'][2]
            newCert.signature_sSig = signcertData_decoded[1]['sSig']
        
        #  -------------------------------------------
        response_path = os.path.join(
            self.path,
            'certificates',
            'responses',
            f'ITS_{vehicle_id}',
            'responseAT.bin'
        )
        self.readFileContent(response_path)
        if self.dataResponse is None or self.length == 0:
            print("Error reading ATResponse.bin file")
            return None
        
        self.ephemeral = False
        self.reconverECKeyPair(self.ephemeral, vehicle_id, ini)
        packetContent = self.dataResponse

        encPacket = cPacket()

        ieeeData_decoded = asn1_modules.decode('Ieee1609Dot2Data', packetContent)
        encPacket.m_protocolversion = ieeeData_decoded['protocolVersion']
        contentDecoded = ieeeData_decoded['content']
        # check the present, here is always signed data
        present1 = contentDecoded[0]

        if present1 == 'encryptedData':
            encDataDec = contentDecoded[1]

            for recip in encDataDec['recipients']:
                present3 = recip[0]
                if present3 == 'pskRecipInfo':
                    encPacket.content.encrData.recipient = recip[1]
            
            # cipher part
            present6 = encDataDec['ciphertext'][0]
            if present6 == 'aes128ccm':  # Changed from 'aes128Ccm' to 'aes128ccm'
                encPacket.content.encrData.ciphertext = encDataDec['ciphertext'][1]['ccmCiphertext']
                encPacket.content.encrData.nonce = encDataDec['ciphertext'][1]['nonce']

        # Decrypt the message
        encPacket.content.unsecuredData = self.doDecryption(
            encPacket.content.encrData.ciphertext,
            encPacket.content.encrData.nonce,
            vehicle_id
        )
        if not encPacket.content.unsecuredData:
            print("[ERR] Error decrypting the message")
            return None  
        
        signedDataDecoded = asn1_modules.decode('Ieee1609Dot2Data', encPacket.content.unsecuredData)
        sPack = cPacket()

        sPack.m_protocolversion = signedDataDecoded['protocolVersion']
        contentDecoded2 = signedDataDecoded['content']
        present7 = contentDecoded2[0]
        if present7 == 'signedData':
            signDec = contentDecoded2[1]
            sPack.content.signData.hashID = signDec['hashId']
            tbsDecoded = signDec['tbsData']
            payload_decoded = tbsDecoded['payload']
            dataContainerDecoded = payload_decoded['data']
            sPack.content.signData.tbsdata.protocolversion = dataContainerDecoded['protocolVersion']
            contentContainerDecoded = dataContainerDecoded['content']
            present8 = contentContainerDecoded[0]
            if present8 == 'unsecuredData':
                sPack.content.signData.tbsdata.unsecuredData = contentContainerDecoded[1]
            sPack.content.signData.tbsdata.header_psid = tbsDecoded['headerInfo']['psid']
            sPack.content.signData.tbsdata.header_generationTime = tbsDecoded['headerInfo']['generationTime']
            present3 = signDec['signer'][0]
            if present3 == 'digerst':
                sPack.content.signData.signer_digest = signDec['signer'][1]
            present9 = signDec['signature'][0]
            if present9 == 'ecdsaNistP256Signature':
                present10 = signDec['signature'][1]['rSig'][0]
                if present10 == 'x-only':
                    sPack.content.signData.rSig.p256_x_only = signDec['signature'][1]['rSig'][1]
                elif present10 == 'fill':
                    sPack.content.signData.rSig.p256_fill = None
                elif present10 == 'compressed-y-0':
                    sPack.content.signData.rSig.p256_compressed_y_0 = signDec['signature'][1]['rSig'][1]
                elif present10 == 'compressed-y-1':
                    sPack.content.signData.rSig.p256_compressed_y_1 = signDec['signature'][1]['rSig'][1]
                elif present10 == 'uncompressed':
                    sPack.content.signData.rSig.p256_uncompressed_x = signDec['signature'][1]['rSig'][1]
                    sPack.content.signData.rSig.p256_uncompressed_y = signDec['signature'][1]['rSig'][2]
                sPack.content.signData.signature_sSig = signDec['signature'][1]['sSig']
            tbs = asn1_modules.encode('ToBeSignedData', tbsDecoded)

            signValidation = self.signatureVerification(
                tbs,
                sPack.content.signData.rSig,
                sPack.content.signData.signature_sSig,
                newCert.tbs.verifyKeyIndicator,
                ini
            )
 
        if signValidation:
            etsiData = asn1_modules.decode('EtsiTs102941Data', sPack.content.signData.tbsdata.unsecuredData)
            etsiVersion = etsiData['version']
            etsiContent = etsiData['content']
            pres = etsiContent[0]

            if pres == 'authorizationResponse':
                res = etsiContent[1]
                ATres = response()
            
                ATres.requestHash = res['requestHash']
                ATres.response_code = res['responseCode']
                is_ok = (ATres.response_code == 'ok') or (ATres.response_code == 0)
                if not is_ok:
                    print(f"[ERR] Response code: {ATres.response_code}")
                    return None
                certDecoded = res['certificate']
                ATres.certificate.version = certDecoded['version']
                ATres.certificate.type = certDecoded['type']
                present11 = certDecoded['issuer'][0]
                if present11 == 'sha256AndDigest':
                    ATres.certificate.issuer = certDecoded['issuer'][1]
                
                if certDecoded['toBeSigned']['id'][0] == 'none':
                    ATres.certificate.tbs.id = 0
                else:
                    ATres.certificate.tbs.name = certDecoded['toBeSigned']['id'][1]
                ATres.certificate.tbs.cracaId = certDecoded['toBeSigned']['cracaId']
                ATres.certificate.tbs.crlSeries = certDecoded['toBeSigned']['crlSeries']
                ATres.certificate.tbs.validityPeriod_start = certDecoded['toBeSigned']['validityPeriod']['start']
                if certDecoded['toBeSigned']['validityPeriod']['duration'][0] == 'hours':
                    ATres.certificate.tbs.validityPeriod_duration = certDecoded['toBeSigned']['validityPeriod']['duration'][1]
                for perm in certDecoded['toBeSigned']['appPermissions']:
                    newServ = GNpsidSsp()
                    newServ.psid = perm['psid']
                    if perm['ssp'][0] == 'bitmapSsp':
                        newServ.bitmapSsp = perm['ssp'][1]
                    ATres.certificate.tbs.appPermissions.append(newServ)
                
                # Filling last certificate field, verifyKeyIndicator.

                if certDecoded['toBeSigned']['verifyKeyIndicator'][0] == 'verificationKey':
                    if certDecoded['toBeSigned']['verifyKeyIndicator'][1][0] == 'ecdsaNistP256':
                        switcher = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][0]
                        if switcher == 'x-only':
                            ATres.certificate.tbs.verifyKeyIndicator.p256_x_only = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                        elif switcher == 'fill':
                            ATres.certificate.tbs.verifyKeyIndicator.p256_fill = None
                        elif switcher == 'compressed-y-0':
                            ATres.certificate.tbs.verifyKeyIndicator.p256_compressed_y_0 = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                        elif switcher == 'compressed-y-1':
                            ATres.certificate.tbs.verifyKeyIndicator.p256_compressed_y_1 = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                        elif switcher == 'uncompressed':
                            ATres.certificate.tbs.verifyKeyIndicator.p256_uncompressed_x = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                            ATres.certificate.tbs.verifyKeyIndicator.p256_uncompressed_y = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][2]
                signCertDecoded = certDecoded['signature']
                if signCertDecoded[0] == 'ecdsaNistP256Signature':
                    present12 = signCertDecoded[1]['rSig'][0]
                    if present12 == 'x-only':
                        ATres.certificate.rSig.p256_x_only = signCertDecoded[1]['rSig'][1]
                    elif present12 == 'fill':
                        ATres.certificate.rSig.p256_fill = None
                    elif present12 == 'compressed-y-0':
                        ATres.certificate.rSig.p256_compressed_y_0 = signCertDecoded[1]['rSig'][1]
                    elif present12 == 'compressed-y-1':
                        ATres.certificate.rSig.p256_compressed_y_1 = signCertDecoded[1]['rSig'][1]
                    elif present12 == 'uncompressed':
                        ATres.certificate.rSig.p256_uncompressed_x = signCertDecoded[1]['rSig'][1]
                        ATres.certificate.rSig.p256_uncompressed_y = signCertDecoded[1]['rSig'][2]
                    ATres.certificate.signature_sSig = signCertDecoded[1]['sSig']
                at = asn1_modules.encode('CertificateBase', certDecoded)
                print("ATResponse successfully parsed")
                print('AT Bytes:', at)

                # inserting the certificate in the database
                CPath = os.path.join(self.path, 'certificates', 'certificates.json')
                cert_entry = {
                    'itsID': ini.itsID,
                    'certificateRaw': at.hex(),
                    'certificate': self._to_serializable(ATres.certificate),
                    'start': ATres.certificate.tbs.validityPeriod_start,
                    'end': ATres.certificate.tbs.validityPeriod_start + ATres.certificate.tbs.validityPeriod_duration * 3600
                }

                try:
                    if os.path.exists(CPath):
                        with open(CPath, 'r') as f:
                            existing_data = json.load(f)
                    else:
                        existing_data = {}
                    vehicle_key = str(vehicle_id)
                    vehicle_entry = existing_data.get(vehicle_key, {})
                    vehicle_entry['AT'] = cert_entry
                    existing_data[vehicle_key] = vehicle_entry
                    with open(CPath, 'w') as f:
                        json.dump(existing_data, f, indent=4)
                    print(f"AT certificate data saved to {CPath}")
                except Exception as e:
                    print(f"Error saving AT certificate data to {CPath}: {e}")

                return ATres.certificate
        else:
            print("Signature verification failed")
            return None

# example of usage
if __name__ == "__main__":
    at_response = ATResponse()
    certificate = at_response.getATResponse(0)
    if certificate:
        print("Extracted Certificate:")
        print(certificate)
    else:
        print("Failed to extract certificate from AT Response.")
