import os
import requests
import hashlib
import asn1tools
import traceback
import sys
import time
import glob
import hmac

from dataclasses import dataclass, field
from typing import List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend
# ASN.1/OER: serve lo schema ASN.1 originale per generare i binding
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key, load_der_public_key,
    load_pem_private_key, load_der_private_key,
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, Prehashed


from .INIReader import INIReader
from .ECResponse import ECResponse
from .CRReader import CRRReader
from dataclasses import dataclass

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

class ATManager:
    def __init__(self, terminatorFlagPtr: bool = None):
        
        self.NONCE_LENGTH = 12
        self.AES_KEY_LENGTH = 16 # AES-128
        self.AES_CCM_TAG_LENGTH = 16
        self.HMAC_TAG_LENGTH = 32
        self.CURVE = ec.SECP256R1()  # NIST P-256

        self.m_terminatorFlagPtr = terminatorFlagPtr
        self.ephemeral = False
        self.m_ecKey = None
        self.m_EPHecKey = None
        self.request_result = None
        self.signedData_result = None
        self.encode_result = None
        self.m_protocolVersion = 3
        self.m_recipientID = None # to be set with AA certificate
        self.m_hashId = 'sha256'  # Changed from hashes.SHA256() to string
        self.m_psid = 623
        self.m_certFormat = 1
        self.m_eaId = 'B4B5395C8CF634B2'
        self.m_hours = 168
        self.m_CAM = 36
        self.m_DENM = 37
        self.m_CPM = 639
        self.m_bitmapSspCAM = '01FFFC'
        self.m_bitmapSspDENM = '01FFFFFF'
        self.m_bitmapSspCPM = '01'

        self.m_ECHex = None 
        self.path = os.path.abspath(os.path.dirname(__file__))

    
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
                with open(file_name, "wb") as file_out:
                    length = len(key)
                    file_out.write(length.to_bytes(8, byteorder="little"))  # Scrivi la lunghezza (size_t, 8 byte)
                    file_out.write(key.encode("utf-8"))  # Scrivi la stringa
                    print("Pre Shared Key saved to binary file.")
            except Exception as e:
                print(f"Error opening file for writing: {e}")
    

    def generateHMACKey(self):
        return os.urandom(self.HMAC_TAG_LENGTH)

    @staticmethod
    def computeHMACTag(hmac_key: bytes, verification_key: bytes) -> bytes:
        hmac_obj = hmac.new(hmac_key, verification_key, hashlib.sha256)
        tag = hmac_obj.digest()
        return tag[:16]
    
    
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
    
    @staticmethod
    def deriveKeyWithKDF2(z: bytes, otherinfo: bytes | None, out_len: int) -> bytes:

        otherinfo = otherinfo or b""
        out = b""
        counter = 1
        while len(out) < out_len:
            c = counter.to_bytes(4, "big")
            out += hashlib.sha256(z + c + otherinfo).digest()
            counter += 1
        return out[:out_len]

    def encryptMessage(self, plaintext: bytes, receiverPublicKey: ec.EllipticCurvePublicKey, p1: bytes | None = None, id: int| None = None):
        # 1) Generate random AES key and nonce
        aesKey = os.urandom(self.AES_KEY_LENGTH)  # AES-128, 128 bit key
        nonce = os.urandom(self.NONCE_LENGTH)     # 12 byte nonce for AES-CCM
        filePath = os.path.join(self.path, 'certificates', 'keys', f'ITS_{id}', "pskAT.bin")

        # Print and save the AES key (matching C++ ATManager behavior)
        aes_key_hex = ''.join(f'{byte:02x}' for byte in aesKey)
        print(f"[INFO] Shared key: {aes_key_hex}")
        self.saveStringToFile(aes_key_hex, filePath)

        # 2) Encrypt with AES-128-CCM (using aesKey and nonce)
        aead = AESCCM(aesKey, tag_length=self.AES_CCM_TAG_LENGTH)
        ct_and_tag = aead.encrypt(nonce, plaintext, None)
        ciphertext = ct_and_tag[:-self.AES_CCM_TAG_LENGTH]
        aesCcmTag = ct_and_tag[-self.AES_CCM_TAG_LENGTH:]

        # 3) Validate receiver's public key and generate ephemeral key for ECDH
        if not isinstance(receiverPublicKey, ec.EllipticCurvePublicKey):
            raise InvalidKey("La chiave pubblica del destinatario non è EC o non è valida.")
        ephemeralKey = ec.generate_private_key(self.CURVE)

        sharedSecret = ephemeralKey.exchange(ec.ECDH(), receiverPublicKey)  # ECDH

        # 4) KDF2(SHA-256) → 48 byte: ke (16) || km (32)
        derivedKey = self.deriveKeyWithKDF2(sharedSecret, p1, 48)
        ke, km = derivedKey[:16], derivedKey[16:]

        # 5) "Encrypt" the AES key with XOR using ke (ECIES style key encapsulation)
        encryptedKey = bytes(a ^ b for a, b in zip(aesKey, ke))

        # 6) HMAC-SHA256(encrypted_key) with km, truncated to 16 bytes
        h = hmac.new(km, encryptedKey, hashlib.sha256)
        full_tag = h.digest()
        ecies_tag = full_tag[:16]

        # 7) Export ephemeral public key in X9.62 uncompressed format (like i2o_ECPublicKey)
        eph_pub_bytes = ephemeralKey.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

        return {
            "ciphertext": ciphertext,
            "encrypted_key": encryptedKey,
            "ephemeral_public_key": eph_pub_bytes,
            "ecies_tag": ecies_tag,
            "nonce": nonce,
            "aesCcmTag": aesCcmTag,
        }
    
    def doEncryption(self, message: bytes, encPkEA: GNecdsaNistP256, p1, id: int | None = None):
        compression = 0
        publicKeyEA = b""
        if encPkEA.p256_x_only:
            publicKeyEA = encPkEA.p256_x_only
        elif encPkEA.p256_compressed_y_0:
            publicKeyEA = encPkEA.p256_compressed_y_0
            compression = 2
        elif encPkEA.p256_compressed_y_1:
            publicKeyEA = encPkEA.p256_compressed_y_1
            compression = 3

        receiver_pub_key = self.loadCompressedPublicKey(publicKeyEA, compression)

        if receiver_pub_key is None:
            print("Failed to load the public key!")
            return None

        data = EncData()
        
        # FIX: Remove extra argument, pass only message, receiver_pub_key, p1, id
        encryption_result = self.encryptMessage(message, receiver_pub_key, p1, id)
        
        data.encryptedKey = encryption_result["encrypted_key"]
        data.ephemeralPublicKey = encryption_result["ephemeral_public_key"]
        data.eciesTag = encryption_result["ecies_tag"]
        data.nonce = encryption_result["nonce"]
        
        # Remove the first byte (0x04 prefix) from ephemeral public key
        data.ephemeralPublicKey = data.ephemeralPublicKey[1:]

        # Extract x and y values (32 bytes each)
        data.x_value = data.ephemeralPublicKey[:32]
        data.y_value = data.ephemeralPublicKey[32:]

        # Concatenate ciphertext and AES CCM tag
        data.ciphertextWithTag = encryption_result["ciphertext"] + encryption_result["aesCcmTag"]

        return data
 
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
    
    def recoverECKeyPair(self, ephemeral: bool, id: int) -> "GNpublicKey":
        public_key = GNpublicKey()
        keys_folder = os.path.join(self.path, 'certificates', 'keys', f'ITS_{id}')
        try:
            if ephemeral:
                private_key_file = os.path.join(keys_folder,"ephSKEY2.pem")
                public_key_file = os.path.join(keys_folder,"ephPKEY2.pem")
                ec_key = self.loadECKeyFromFile(private_key_file, public_key_file)
                if ec_key is None:
                    return public_key
                # Memorizza come chiave ephemeral
                self.m_EPHecKey = ec_key
            else:

                private_key_file = os.path.join(keys_folder,"ephSKEY.pem")
                public_key_file = os.path.join(keys_folder,"ephPKEY.pem")
                ec_key = self.loadECKeyFromFile(private_key_file, public_key_file)
                if ec_key is None:
                    return public_key
                # Memorizza come chiave principale
                self.m_ecKey = ec_key

            # Estrae la parte pubblica e determina il prefisso (parità di y)
            pub_numbers = ec_key.public_key().public_numbers()
            
            x_bytes = pub_numbers.x.to_bytes(32, "big")
            y_is_even = (pub_numbers.y % 2) == 0
            prefix_type = 'compressed_y_0' if y_is_even else 'compressed_y_1'

            # Estrae la parte pubblica in formato compresso
            pub_key = ec_key.public_key()
            
            # Ottieni la chiave compressa usando cryptography
            compressed_point = pub_key.public_bytes(
                Encoding.X962, 
                PublicFormat.CompressedPoint
            )
            
            # Il primo byte è il prefisso (0x02 o 0x03), i successivi 32 sono la coordinata x
            prefix_byte = compressed_point[0]
            x_bytes = compressed_point[1:33]
            
            prefix_type = 'compressed_y_0' if prefix_byte == 0x02 else 'compressed_y_1'

            public_key.pk = x_bytes
            public_key.prefix = prefix_type
            return public_key
        except Exception as e:
            print("Error recovering EC key pair", file=sys.stderr)
            return public_key

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
    
    def signatureCreation(self, tbsData: bytes, ephemeral: bool, signer_hex: str | None = None) -> GNsignMaterial | None:

        try:
            signMaterial = GNsignMaterial()

            # Se signer_hex non è fornito, usa un byte array vuoto (comportamento "self")
            if signer_hex:
                signer_bytes =signer_hex
            else:
                signer_bytes = b''

            # Calcola gli hash individuali
            tbsData_hash = self.computeSHA256(tbsData)
            signer_hash = self.computeSHA256(signer_bytes)

            # Concatena gli hash e calcola l'hash finale
            concatenatedHashes = tbsData_hash + signer_hash
            final_hash = self.computeSHA256(concatenatedHashes)

            # Seleziona la chiave corretta
            if ephemeral:
                if self.m_EPHecKey is None:
                    print("Ephemeral EC key not loaded", file=sys.stderr)
                    return None
                ec_key = self.m_EPHecKey
            else:
                if self.m_ecKey is None:
                    print("Main EC key not loaded", file=sys.stderr)
                    return None
                ec_key = self.m_ecKey

            # Firma l'hash finale
            signature = self.signHash(final_hash, ec_key)
            if signature is None:
                return None # Errore già stampato da signHash

            # Estrai r e s e normalizzali a 32 byte
            r_int, s_int = decode_dss_signature(signature)
            
            signMaterial.r = r_int.to_bytes(32, byteorder='big')
            signMaterial.s = s_int.to_bytes(32, byteorder='big')

            return signMaterial
        except Exception as e:
            print(f"Error during signature creation: {e}", file=sys.stderr)
            traceback.print_exc()
            return None
    
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
    def getCurrentTimestamp32() -> int:

        seconds_since_epoch = int(time.time())

        # Costanti come nel C++
        seconds_per_year = 365 * 24 * 60 * 60
        leap_seconds = 8 * 24 * 60 * 60
        epoch_difference_seconds = (34 * seconds_per_year) + leap_seconds

        tai_seconds_since_2004 = seconds_since_epoch - epoch_difference_seconds

        # Emula il cast a uint32_t del C++ (wrap modulo 2^32)
        return tai_seconds_since_2004 & 0xFFFFFFFF
    
    def readIniFile(self, id) -> "IniAT":
        """Python translation of ATManager::readIniFile().
        Reads PKI_info.ini using INIReader and returns an IniAT with defaults of "UNKNOWN" like the C++ code.
        Prints an error if the file can't be loaded (ParseError() < 0).
        """
        ini_path = os.path.join(self.path, 'certificates', 'PKI_info.ini')
        credentials = os.path.join(self.path, 'certificates', 'credentials.json')
        
        reader = INIReader(ini_path)
        if reader.ParseError() < 0:
            print(f"[ERR] Can't load '{ini_path}'")
        
        credentials = CRRReader(credentials, id)
        if credentials is None:
            print(f"[ERR] Can't load credentials from '{credentials}'", file=sys.stderr)
            return None
        
        ini = IniAT(
            aaCert1=reader.Get("ATinfo", "AAcert1", "UNKNOWN"),
            aaCert2=reader.Get("ATinfo", "AAcert2", "UNKNOWN"),
            aaCert3=reader.Get("ATinfo", "AAcert3", "UNKNOWN"),
            aaCert4=reader.Get("ATinfo", "AAcert4", "UNKNOWN"),
            recipientAA=reader.Get("ATinfo", "recipientAA", "UNKNOWN"),
            bitmapCAM=reader.Get("ATinfo", "bitmapCAM", "UNKNOWN"),
            bitmapDENM=reader.Get("ATinfo", "bitmapDENM", "UNKNOWN"),
            eaIDstring=reader.Get("ATinfo", "eaIDstring", "UNKNOWN"),
        )
        self.AACertificate = bytes.fromhex(ini.aaCert1+ini.aaCert2+ini.aaCert3+ini.aaCert4)
        return ini
    
    def regeneratePEM(self,id):
        """Generate new EC key pair and save to PEM files"""
        keys_folder = os.path.join(self.path, 'certificates', 'keys', f'ITS_{id}')

        priv_path = os.path.join(keys_folder,'ephSKEY2.pem')
        pub_path = os.path.join(keys_folder,'ephPKEY2.pem')
        
        try:
            # Create output directory if missing
            priv_dir = os.path.dirname(priv_path) or "."
            os.makedirs(priv_dir, exist_ok=True)
            
            # Generate key pair on NID_X9_62_prime256v1 (aka SECP256R1)
            try:
                ec_key = ec.generate_private_key(ec.SECP256R1())
            except Exception as e:
                print("Error creating EC_KEY object", file=sys.stderr)
                self.print_openssl_error()
                return

            try:
                priv_pem = ec_key.private_bytes(
                    Encoding.PEM,
                    PrivateFormat.TraditionalOpenSSL,
                    NoEncryption(),
                )
            except Exception as e:
                print("Error generating EC key pair", file=sys.stderr)
                self.print_openssl_error()
                return
                
            # Write private key
            try:
                with open(priv_path, "wb") as f:
                    f.write(priv_pem)
            except Exception as e:
                print("Error opening file for writing private key", file=sys.stderr)
                return
                
            # Serialize public key in SubjectPublicKeyInfo PEM (matches PEM_write_EC_PUBKEY)
            try:
                pub_pem = ec_key.public_key().public_bytes(
                    Encoding.PEM,
                    PublicFormat.SubjectPublicKeyInfo,
                )
            except Exception as e:
                print("Error writing public key to PEM file", file=sys.stderr)
                self.print_openssl_error()
                return
                
            # Write public key
            try:
                with open(pub_path, "wb") as f:
                    f.write(pub_pem)
            except Exception as e:
                print("Error opening file for writing public key", file=sys.stderr)
                return
                
            print("Key pair generated and saved to ephSKEY2.pem and ephPKEY2.pem")
            
        except Exception as e:
            print("Error generating EC key pair", file=sys.stderr)
            return
    
    def createRequest(self,id):

        if self.m_ECHex is None:
            print("[ERROR] Critical error: m_ECHex is None. Cannot create any request.", file=sys.stderr)
            self.m_terminatorFlagPtr = True
            return None
        
        iniData = self.readIniFile(id)
        asn_folder = os.path.join("data", "asn", "security")
        asn_files = glob.glob(os.path.join(asn_folder, "*.asn"))
        if not asn_files:
            print(f"[ERR] No ASN.1 file found in {asn_folder}")
            return None
        
        asn1_modules = asn1tools.compile_files(asn_files, 'oer')
        AAcertificate = self.AACertificate
        certificate_hash = self.computeSHA256(AAcertificate)
        certContent = AAcertificate

        certData_decoded = asn1_modules.decode('CertificateBase', certContent)
        newCert = GNcertificateDC()
        newCert.version = certData_decoded['version']
        newCert.type = certData_decoded['type']
        newCert.issuer = certData_decoded['issuer'][1]

        if certData_decoded['toBeSigned']['id'][0] == 'none':
            newCert.tbs.id = 0
        elif certData_decoded['toBeSigned']['id'][0] == 'name':
            newCert.tbs.name = certData_decoded['toBeSigned']['id'][1]
        
        newCert.tbs.cracaId = certData_decoded['toBeSigned']['cracaId']
        newCert.tbs.crlSeries = certData_decoded['toBeSigned']['crlSeries']
        newCert.tbs.validityPeriod_start = certData_decoded['toBeSigned']['validityPeriod']['start']

        if certData_decoded['toBeSigned']['validityPeriod']['duration'][0] == 'hours':
            newCert.tbs.validityPeriod_duration = certData_decoded['toBeSigned']['validityPeriod']['duration'][1]
        
        for perm in certData_decoded['toBeSigned']['appPermissions']:
            newServ = GNpsidSsp()
            newServ.psid = perm['psid']
            servicePermission = perm['ssp']
            if servicePermission[0] == 'bitmapSsp':
                newServ.bitmapSsp = servicePermission[1]
            
            newCert.tbs.appPermissions.append(newServ)
        
        newCert.tbs.symAlgEnc = certData_decoded['toBeSigned']['encryptionKey']['supportedSymmAlg']

        if certData_decoded['toBeSigned']['encryptionKey']['publicKey'][0] == 'eciesNistP256':
            switcher = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][0]
            if switcher == 'x-only':
                newCert.tbs.encPublicKey.p256_x_only = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
            elif switcher == 'fill':
                newCert.tbs.encPublicKey.p256_fill = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
            elif switcher == 'compressed-y-0':
                newCert.tbs.encPublicKey.p256_compressed_y_0 = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
            elif switcher == 'compressed-y-1':
                newCert.tbs.encPublicKey.p256_compressed_y_1 = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
            elif switcher == 'uncompressedP256':
                newCert.tbs.encPublicKey.p256_uncompressed_x = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
                newCert.tbs.encPublicKey.p256_uncompressed_y = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][2]
        
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
                elif switcher == 'uncompressedP256':
                    newCert.tbs.verifyKeyIndicator.p256_uncompressed_x = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                    newCert.tbs.verifyKeyIndicator.p256_uncompressed_y = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][2]
        
        signcertData_decoded = certData_decoded['signature']
        present = signcertData_decoded[0]
        if present == 'ecdsaNistP256Signature':
            present4 =  signcertData_decoded[1]['rSig'][0]
            if present4 == 'x_only':
                newCert.rSig.p256_x_only = signcertData_decoded[1]['rSig'][1]
            elif present4 == 'fill':
                newCert.rSig.p256_fill = None
            elif present4 == 'compressed_y_0':
                newCert.rSig.p256_compressed_y_0 = signcertData_decoded[1]['rSig'][1]
            elif present4 == 'compressed_y_1':
                newCert.rSig.p256_compressed_y_1 = signcertData_decoded[1]['rSig'][1]
            elif present4 == 'uncompressedP256':
                newCert.rSig.p256_uncompressed_x = signcertData_decoded[1]['rSig'][1]
                newCert.rSig.p256_uncompressed_y = signcertData_decoded[1]['rSig'][2]
            newCert.signature_sSig = signcertData_decoded[1]['sSig']
        
        self.ephemeral = True
        # FIX: Always pass id to recoverECKeyPair
        EPHpublic_key = self.recoverECKeyPair(self.ephemeral, id)
        self.ephemeral = False
        public_key = self.recoverECKeyPair(self.ephemeral, id)

        m_generationTime = self.getCurrentTimestamp()

        # ---------- EtsiTs1030971Data-Signed ----------------
        ieeeData = {}
        ieeeData['protocolVersion'] = self.m_protocolVersion
        contentContainer1 = ['signedData']
        signData = {}
        signData['hashId'] = self.m_hashId
        tbs = {}
        signPayload = {}
        dataPayload2 = {}
        dataPayload2['protocolVersion'] = self.m_protocolVersion
        # ---------- EtsiTs102941Data ----------------
        dataContentPayload2 = ['unsecuredData']
        dataPayload102 = {}
        # TODO: verificare se va messo il version = 1
        dataPayload102['version'] = 1
        dataContentPayload102 = ['authorizationRequest']
        # ---------- AT request-------------
        InnerRequest = {}
        InnerRequest['publicKeys'] = {}
        if EPHpublic_key.prefix == 'compressed_y_0':
            InnerRequest['publicKeys']['verificationKey'] = ('ecdsaNistP256', ('compressed-y-0', EPHpublic_key.pk))
        elif EPHpublic_key.prefix == 'compressed_y_1':
            InnerRequest['publicKeys']['verificationKey'] = ('ecdsaNistP256', ('compressed-y-1', EPHpublic_key.pk))
        
        hmacKey = self.generateHMACKey()
        m_hmacKey = hmacKey

        if EPHpublic_key.prefix == "compressed_y_0":
            verificationKey = ('ecdsaNistP256',('compressed-y-0', EPHpublic_key.pk))
        elif EPHpublic_key.prefix == "compressed_y_1":
            verificationKey = ('ecdsaNistP256',('compressed-y-1', EPHpublic_key.pk))
        
        verkey = asn1_modules.encode('PublicVerificationKey', verificationKey)
        ver_key = verkey

        keyTag = self.computeHMACTag(hmacKey,ver_key)
        m_keyTag = keyTag
        InnerRequest['hmacKey'] = m_hmacKey
        ea_id = bytes.fromhex(iniData.eaIDstring)
        InnerRequest['sharedAtRequest'] = {}
        InnerRequest['sharedAtRequest']['eaId'] = ea_id
        InnerRequest['sharedAtRequest']['keyTag'] = m_keyTag
        InnerRequest['sharedAtRequest']['certificateFormat'] = self.m_certFormat
        validity = {}
        m_start = self.getCurrentTimestamp32()
        validity['start'] = m_start
        validity['duration'] = ('hours', self.m_hours)
        InnerRequest['sharedAtRequest']['requestedSubjectAttributes'] = {}
        InnerRequest['sharedAtRequest']['requestedSubjectAttributes']['validityPeriod'] = validity
        
        appPermission = []
        psid1 = {}
        psid1['psid'] = self.m_CAM
        servicePermission1 = ('bitmapSsp', bytes.fromhex(self.m_bitmapSspCAM))
        psid1['ssp'] = servicePermission1
        appPermission.append(psid1)
        psid2 = {}
        psid2['psid'] = self.m_DENM
        psid2['ssp'] = ('bitmapSsp', bytes.fromhex(self.m_bitmapSspDENM))
        appPermission.append(psid2)
        
        InnerRequest['sharedAtRequest']['requestedSubjectAttributes']['appPermissions'] = appPermission
        
        sharedAT = {}
        sharedAT['eaId'] = ea_id
        sharedAT['keyTag'] = m_keyTag
        sharedAT['certificateFormat'] = self.m_certFormat
        sharedAT['requestedSubjectAttributes'] = {}
        sharedAT['requestedSubjectAttributes']['validityPeriod'] = validity
        sharedAT['requestedSubjectAttributes']['appPermissions'] = appPermission
        shared = asn1_modules.encode('SharedAtRequest', sharedAT)

        sharedAtRequest_hash = self.computeSHA256(shared)
        m_sharedAT = sharedAtRequest_hash
        
        InnerRequest['ecSignature'] = ('ecSignature',{})
        InnerRequest['ecSignature'][1]['protocolVersion'] = self.m_protocolVersion
        contentInner = ['signedData']
        signData3 = {}
        signData3['hashId'] = self.m_hashId
        tbs3 = {}
        signPayload3 = {}
        hashData = ('sha256HashedData',m_sharedAT)
        signPayload3['extDataHash'] = hashData
        tbs3['payload'] = signPayload3
        tbs3['headerInfo'] = {}
        tbs3['headerInfo']['psid'] = self.m_psid
        tbs3['headerInfo']['generationTime'] = m_generationTime
        signData3['tbsData'] = tbs3

        tbs = asn1_modules.encode('ToBeSignedData', tbs3)
        ec_hex = self.m_ECHex
        sign_material = self.signatureCreation(tbs, self.ephemeral, ec_hex)
        digest = ec_hex
        digest_hash = self.computeSHA256(digest)
        ec_h8 = digest_hash[24:32]
        m_digest = ec_h8
        signData3['signer'] = ('digest', m_digest)
        signatureContentInner = ('ecdsaNistP256Signature',{})
        signatureContentInner[1]['rSig'] = ('x-only', sign_material.r)
        signatureContentInner[1]['sSig'] = sign_material.s
        signData3['signature'] = signatureContentInner
        contentInner.append(signData3)
        contentInner = tuple(contentInner)
        InnerRequest['ecSignature'][1]['content'] = contentInner

        dataContentPayload102.append(InnerRequest)
        dataContentPayload102 = tuple(dataContentPayload102)
        dataPayload102['content'] = dataContentPayload102
        at_request = asn1_modules.encode('EtsiTs102941Data', dataPayload102)

        dataContentPayload2 = ('unsecuredData', at_request)
        dataPayload2['content'] = dataContentPayload2
        signPayload['data'] = dataPayload2
        tbs = {}
        tbs['payload'] = signPayload
        tbs['headerInfo'] = {}
        tbs['headerInfo']['psid'] = self.m_psid
        tbs['headerInfo']['generationTime'] = m_generationTime
        signData['tbsData'] = tbs
        # ---------- EtsiTs102941Data ----------------
        tbs_hexOuter = asn1_modules.encode('ToBeSignedData', tbs)
        self.ephemeral = True
        sign_materialOuter = self.signatureCreation(tbs_hexOuter, self.ephemeral)
        signData['signer'] = ('self', None)
        signatureContent = ('ecdsaNistP256Signature',{})
        signatureContent[1]['rSig'] = ('x-only', sign_materialOuter.r)
        signatureContent[1]['sSig'] = sign_materialOuter.s
        signData['signature'] = signatureContent
        contentContainer1.append(signData)
        contentContainer1 = tuple(contentContainer1)
        ieeeData['content'] = contentContainer1

        signedData_result = asn1_modules.encode('Ieee1609Dot2Data', ieeeData)

        # ---------- DATA ENCRYPTED ENCODING PART ----------------
        # FIX: Pass id to doEncryption, which will pass it to encryptMessage
        dataEnc = self.doEncryption(signedData_result, newCert.tbs.encPublicKey, certificate_hash, id)
        ieeeData2 = {}
        ieeeData2['protocolVersion'] = self.m_protocolVersion
        contentContainer = ('encryptedData',{})

        recipientsSeq = []
        recipInfo = ('certRecipInfo',{})
        recipient = bytes.fromhex(iniData.recipientAA)
        recID = recipient
        recipInfo[1]['recipientId'] = recID
        recipInfo[1]['encKey'] = ('eciesNistP256',{})

        encKey = dataEnc.encryptedKey
        recipInfo[1]['encKey'][1]['c'] = encKey
        eciesTag = dataEnc.eciesTag
        recipInfo[1]['encKey'][1]['t'] = eciesTag
        recipInfo[1]['encKey'][1]['v'] = ('uncompressedP256',{'x': dataEnc.x_value,'y': dataEnc.y_value})
        recipientsSeq.append(tuple(recipInfo))
        contentContainer[1]['recipients'] = recipientsSeq

        contentContainer[1]['ciphertext'] = ('aes128ccm',{})
        contentContainer[1]['ciphertext'][1]['nonce'] = dataEnc.nonce
        contentContainer[1]['ciphertext'][1]['ccmCiphertext'] = dataEnc.ciphertextWithTag

        ieeeData2['content'] = contentContainer
        encode_result = asn1_modules.encode('Ieee1609Dot2Data', ieeeData2)

        # Saving the binary file for the request
        try:
            request_dir = os.path.join(self.path, 'certificates', 'requests', f'ITS_{id}')
            request_path = os.path.join(request_dir, 'requestAT.bin')
            with open(request_path, "wb") as f:
                f.write(encode_result)
        except Exception as e:
            print("Error opening file for writing the request", file=sys.stderr)
            self.print_error(e)
            return None
        
        # Calculating request ID (16-byte SHA256 hash of the payload)
        request_id_full = self.computeSHA256(encode_result)
        request_id = request_id_full[:16]
        request_id_hex = ''.join(f'{byte:02x}' for byte in request_id
        )
        print(f"[INFO] Request ID: {request_id_hex}")
    
    def sendPOST(self,id):
        try:
            request_dir = os.path.join(self.path, 'certificates', 'requests', f'ITS_{id}')
            response_dir = os.path.join(self.path, 'certificates','responses', f'ITS_{id}')
            request_path = os.path.join(request_dir, 'requestAT.bin')
            response_path = os.path.join(response_dir, 'responseAT.bin')

            # Ensure output directory exists
            response_dir = os.path.dirname(response_path)
            if response_dir:
                os.makedirs(response_dir, exist_ok=True)

            # FIX: Check if request_path exists, not response_path
            if not os.path.exists(request_path):
                print(f"[ERR] File '{request_path}' does not exist.")
                return

            # Read the binary request file
            with open(request_path, 'rb') as f:
                file_data = f.read()

            # URL and headers matching C++ implementation
            url = "http://0.atos-aa.l0.c-its-pki.eu/"
            headers = {
                "Content-Type": "application/x-its-request"
            }

            # Send POST request
            response = requests.post(url, data=file_data, headers=headers, timeout=30)
            response.raise_for_status()

            # Save response to binary file
            with open(response_path, 'wb') as f:
                f.write(response.content)

            print(f"[INFO] Response saved to {response_path}")

        except requests.exceptions.RequestException as e:
            print(f"[ERR] Request failed, error: {e}")
        except Exception as e:
            print(f"[ERR] Error during POST request: {e}")

# example usage:
if __name__ == "__main__":
    manager = ATManager()
    ec_response = ECResponse()
    ec_response.ephemeral = False
    certificate = ec_response.getECResponse()
    print(ec_response.m_ecBytesStr.hex())
    manager.m_ECHex = ec_response.m_ecBytesStr
    manager.regeneratePEM()  # Generate new ephemeral key pair
    manager.createRequest()   # Create and save the AT request
    manager.sendPOST()      # Send the request via HTTP POST