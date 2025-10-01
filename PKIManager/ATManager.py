import os
import requests
import hashlib
import asn1tools
import traceback
import sys
import time
import glob
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend
# ASN.1/OER: requires the original ASN.1 schema to generate the bindings
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
from .utils.exceptions import SecurityError, SecurityConfigurationError
from .utils.security_models import (
    GNpublicKey,
    GNpsidSsp,
    GNecdsaNistP256,
    GNcertificateDC,
    GNsignMaterial,
    EncData,
    IniAT,
)


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
                    raise SecurityError(f"Error reading length from '{file_name}'")
                length = int.from_bytes(length_bytes, byteorder="little")
                key_bytes = file_in.read(length)
                key = key_bytes.decode("utf-8")
                print(f"Pre Shared Key retrieved: {key}")
        except FileNotFoundError as e:
            raise SecurityError(f"Pre-shared key file '{file_name}' not found") from e
        except OSError as e:
            raise SecurityError(f"Error opening file '{file_name}' for reading") from e
        except Exception as e:
            raise SecurityError(f"Failed to retrieve pre-shared key from '{file_name}'") from e
        return key

    @staticmethod
    def saveStringToFile(key: str, file_name: str):
        try:
            with open(file_name, "wb") as file_out:
                length = len(key)
                file_out.write(length.to_bytes(8, byteorder="little"))  # Write the length (size_t, 8 bytes)
                file_out.write(key.encode("utf-8"))  # Write the string
                print("Pre Shared Key saved to binary file.")
        except OSError as e:
            raise SecurityError(f"Failed to persist pre-shared key to '{file_name}'") from e
    

    def generateHMACKey(self):
        return os.urandom(self.HMAC_TAG_LENGTH)

    @staticmethod
    def computeHMACTag(hmac_key: bytes, verification_key: bytes) -> bytes:
        hmac_obj = hmac.new(hmac_key, verification_key, hashlib.sha256)
        tag = hmac_obj.digest()
        return tag[:16]
    
    
    def loadCompressedPublicKey(self, compressed_key: bytes, compression: int):
        
        if len(compressed_key) != 32:
            raise SecurityError("Compressed public key must be 32 bytes long")
        # Prefix: 0x02 (even y) or 0x03 (odd y)
        if compression == 2:
            pk_data = b'\x02'
        elif compression == 3:
            pk_data = b'\x03'
        else:
            raise SecurityError("Compression must be 2 or 3 for EC public keys")

        pk_data = pk_data + compressed_key
        if len(pk_data) != 33:
            raise SecurityError("Compressed key with prefix must be exactly 33 bytes")
        # Load the ECC public key from compressed bytes
        try:
            evp_pkey = ec.EllipticCurvePublicKey.from_encoded_point(self.CURVE, pk_data)            
            return evp_pkey
        
        except Exception as e:
            raise SecurityError("Failed to convert compressed public key") from e
        
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
        self.saveStringToFile(aes_key_hex, filePath)

        # 2) Encrypt with AES-128-CCM (using aesKey and nonce)
        aead = AESCCM(aesKey, tag_length=self.AES_CCM_TAG_LENGTH)
        ct_and_tag = aead.encrypt(nonce, plaintext, None)
        ciphertext = ct_and_tag[:-self.AES_CCM_TAG_LENGTH]
        aesCcmTag = ct_and_tag[-self.AES_CCM_TAG_LENGTH:]

        # 3) Validate receiver's public key and generate ephemeral key for ECDH
        if not isinstance(receiverPublicKey, ec.EllipticCurvePublicKey):
            raise InvalidKey("The recipient's public key is not an EC key or is invalid.")
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
        except OSError as e:
            raise SecurityError(f"Unable to open private key file '{private_key_file}'") from e
        ec_key = None
        try:
            ec_key = load_pem_private_key(priv_file, password=password)
        except Exception as e:
            raise SecurityError(f"Unable to read private key from '{private_key_file}'") from e
        if not isinstance(ec_key, ec.EllipticCurvePrivateKey):
            raise SecurityError("Loaded private key is not an EC key")
        try:
            with open(public_key_file, 'rb') as f:
                pub_bytes = f.read()
        except OSError as e:
            raise SecurityError(f"Unable to open public key file '{public_key_file}'") from e
        try:
            pub_key = load_pem_public_key(pub_bytes)
        except Exception as e:
            raise SecurityError(f"Unable to read public key from '{public_key_file}'") from e
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            raise SecurityError("Loaded public key is not an EC key")

        if not isinstance(ec_key.curve, type(self.CURVE)) or not isinstance(pub_key.curve, type(self.CURVE)):
            raise SecurityError("EC curve mismatch or unsupported curve")
        
        priv_pub_numbers = ec_key.public_key().public_numbers()
        loaded_pub_numbers = pub_key.public_numbers()
        if (priv_pub_numbers.x != loaded_pub_numbers.x) or (priv_pub_numbers.y != loaded_pub_numbers.y):
            raise SecurityError("Public key does not match the private key")
        return ec_key
    
    def recoverECKeyPair(self, ephemeral: bool, id: int) -> "GNpublicKey":
        public_key = GNpublicKey()
        keys_folder = os.path.join(self.path, 'certificates', 'keys', f'ITS_{id}')

        if ephemeral:
            private_key_file = os.path.join(keys_folder, "ephSKEY2.pem")
            public_key_file = os.path.join(keys_folder, "ephPKEY2.pem")
            ec_key = self.loadECKeyFromFile(private_key_file, public_key_file)
            self.m_EPHecKey = ec_key
        else:
            private_key_file = os.path.join(keys_folder, "ephSKEY.pem")
            public_key_file = os.path.join(keys_folder, "ephPKEY.pem")
            ec_key = self.loadECKeyFromFile(private_key_file, public_key_file)
            self.m_ecKey = ec_key

        pub_numbers = ec_key.public_key().public_numbers()

        x_bytes = pub_numbers.x.to_bytes(32, "big")
        y_is_even = (pub_numbers.y % 2) == 0
        prefix_type = 'compressed_y_0' if y_is_even else 'compressed_y_1'

        compressed_point = ec_key.public_key().public_bytes(
            Encoding.X962,
            PublicFormat.CompressedPoint
        )

        prefix_byte = compressed_point[0]
        x_bytes = compressed_point[1:33]

        prefix_type = 'compressed_y_0' if prefix_byte == 0x02 else 'compressed_y_1'

        public_key.pk = x_bytes
        public_key.prefix = prefix_type
        return public_key

    def signHash(self, hash: bytes, ec_private_key: ec.EllipticCurvePrivateKey) -> bytes:

        try:
            if not isinstance(hash, (bytes, bytearray)):
                raise SecurityError("Hash value must be bytes")
            if len(hash) != 32:
                raise SecurityError("Expected a 32-byte SHA-256 digest")

            return ec_private_key.sign(hash, ec.ECDSA(Prehashed(hashes.SHA256())))
        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError("Error signing hash") from e
    
    def signatureCreation(self, tbsData: bytes, ephemeral: bool, signer_hex: bytes | None = None) -> GNsignMaterial:

        try:
            signMaterial = GNsignMaterial()

            signer_bytes = signer_hex if signer_hex else b''

            tbsData_hash = self.computeSHA256(tbsData)
            signer_hash = self.computeSHA256(signer_bytes)

            concatenatedHashes = tbsData_hash + signer_hash
            final_hash = self.computeSHA256(concatenatedHashes)

            if ephemeral:
                if self.m_EPHecKey is None:
                    raise SecurityError("Ephemeral EC key not loaded")
                ec_key = self.m_EPHecKey
            else:
                if self.m_ecKey is None:
                    raise SecurityError("Main EC key not loaded")
                ec_key = self.m_ecKey

            signature = self.signHash(final_hash, ec_key)

            r_int, s_int = decode_dss_signature(signature)

            signMaterial.r = r_int.to_bytes(32, byteorder='big')
            signMaterial.s = s_int.to_bytes(32, byteorder='big')

            return signMaterial
        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError("Error during signature creation") from e
    
    @staticmethod
    def getCurrentTimestamp() -> int:
        # Microseconds since the current UNIX epoch
        microseconds_since_epoch = time.time_ns() // 1000

        seconds_per_year = 365 * 24 * 60 * 60
        leap_seconds = 8 * 24 * 60 * 60
        epoch_difference_seconds = (34 * seconds_per_year) + leap_seconds
        epoch_difference = epoch_difference_seconds * 1_000_000

        return (microseconds_since_epoch - epoch_difference)

    @staticmethod
    def getCurrentTimestamp32() -> int:

        seconds_since_epoch = int(time.time())

        # Constants aligned with the C++ implementation
        seconds_per_year = 365 * 24 * 60 * 60
        leap_seconds = 8 * 24 * 60 * 60
        epoch_difference_seconds = (34 * seconds_per_year) + leap_seconds

        tai_seconds_since_2004 = seconds_since_epoch - epoch_difference_seconds

        # Emulates the uint32_t cast from the C++ code (wrap modulo 2^32)
        return tai_seconds_since_2004 & 0xFFFFFFFF
    
    def readIniFile(self, id) -> "IniAT":
        """Python translation of ATManager::readIniFile().
        Reads PKI_info.ini using INIReader and returns an IniAT with defaults of "UNKNOWN" like the C++ code.
        Prints an error if the file can't be loaded (ParseError() < 0).
        """
        ini_path = os.path.join(self.path, 'certificates', 'PKI_info.ini')
        credentials_path = os.path.join(self.path, 'certificates', 'credentials.json')

        reader = INIReader(ini_path)
        if reader.ParseError() < 0:
            raise SecurityConfigurationError(f"Can't load '{ini_path}'")

        credentials = CRRReader(credentials_path, id)
        if credentials is None:
            raise SecurityConfigurationError(
                f"Can't load credentials from '{credentials_path}' for vehicle '{id}'"
            )
        
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
            priv_dir = os.path.dirname(priv_path) or "."
            os.makedirs(priv_dir, exist_ok=True)
        except OSError as e:
            raise SecurityError(f"Unable to create directory '{priv_dir}' for key generation") from e

        try:
            ec_key = ec.generate_private_key(self.CURVE)
        except Exception as e:
            raise SecurityError("Error creating EC key pair") from e

        try:
            priv_pem = ec_key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )
        except Exception as e:
            raise SecurityError("Error serializing private EC key") from e

        try:
            with open(priv_path, "wb") as f:
                f.write(priv_pem)
        except OSError as e:
            raise SecurityError(f"Error writing private key to '{priv_path}'") from e

        try:
            pub_pem = ec_key.public_key().public_bytes(
                Encoding.PEM,
                PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception as e:
            raise SecurityError("Error serializing public EC key") from e

        try:
            with open(pub_path, "wb") as f:
                f.write(pub_pem)
        except OSError as e:
            raise SecurityError(f"Error writing public key to '{pub_path}'") from e

        print("Key pair generated and saved to ephSKEY2.pem and ephPKEY2.pem")
    
    def createRequest(self,id):

        if self.m_ECHex is None:
            self.m_terminatorFlagPtr = True
            raise SecurityError("Critical error: m_ECHex is None. Cannot create request.")
        
        iniData = self.readIniFile(id)
        asn_folder = os.path.join("data", "asn", "security")
        asn_files = glob.glob(os.path.join(asn_folder, "*.asn"))
        if not asn_files:
            raise SecurityConfigurationError(f"No ASN.1 file found in '{asn_folder}'")
        
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
        # TODO: verify whether version should be set to 1
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
        request_dir = os.path.join(self.path, 'certificates', 'requests', f'ITS_{id}')
        request_path = os.path.join(request_dir, 'requestAT.bin')
        try:
            os.makedirs(request_dir, exist_ok=True)
            with open(request_path, "wb") as f:
                f.write(encode_result)
        except OSError as e:
            raise SecurityError(f"Error writing AT request to '{request_path}'") from e
        
        # Calculating request ID (16-byte SHA256 hash of the payload)
        request_id_full = self.computeSHA256(encode_result)
        request_id = request_id_full[:16]
        request_id_hex = ''.join(f'{byte:02x}' for byte in request_id
        )
        print(f"[INFO] Request ID: {request_id_hex}")
    
    def sendPOST(self,id):
        request_dir = os.path.join(self.path, 'certificates', 'requests', f'ITS_{id}')
        response_dir = os.path.join(self.path, 'certificates','responses', f'ITS_{id}')
        request_path = os.path.join(request_dir, 'requestAT.bin')
        response_path = os.path.join(response_dir, 'responseAT.bin')

        try:
            os.makedirs(response_dir, exist_ok=True)
        except OSError as e:
            raise SecurityError("Unable to prepare directory for AT response") from e

        try:
            with open(request_path, 'rb') as f:
                file_data = f.read()
        except FileNotFoundError as e:
            raise SecurityError(f"AT request payload '{request_path}' not found") from e
        except OSError as e:
            raise SecurityError(f"Unable to read AT request from '{request_path}'") from e

        url = "http://0.atos-aa.l0.c-its-pki.eu/"
        headers = {
            "Content-Type": "application/x-its-request"
        }

        try:
            response = requests.post(url, data=file_data, headers=headers, timeout=30)
            response.raise_for_status()
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else "unknown"
            body_text = e.response.text if e.response is not None else str(e)
            raise SecurityError(f"AA POST failed with status {status}: {body_text}") from e
        except requests.RequestException as e:
            raise SecurityError("Error during POST request to AA") from e

        try:
            with open(response_path, 'wb') as f:
                f.write(response.content)
        except OSError as e:
            raise SecurityError(f"Unable to write AT response to '{response_path}'") from e

        return response_path
