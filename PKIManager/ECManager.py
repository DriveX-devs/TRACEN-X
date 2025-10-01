import os
import requests
import hashlib
import asn1tools
import traceback
import sys
import time
import glob

from cryptography.hazmat.primitives import hashes, hmac
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
from .CRReader import CRRReader
from .ECResponse import ECResponse
from .utils.exceptions import SecurityError, SecurityConfigurationError
from .utils.security_models import (
    EncData,
    GNcertificateDC,
    GNecdsaNistP256,
    GNpsidSsp,
    GNpublicKey,
    GNsignMaterial,
    IniEC,
)


class ECManager:
    """ Request of certificates """
    def __init__(self):
        self.ephemeral = False                # Flag for ephemeral key usage
        self.m_ecKey = None                   # Primary EC key
        self.m_EPHecKey = None                # Ephemeral EC key
        self.request_result = ""              # Buffer for the generated request
        self.signedData_result = ""           # Buffer for signed data
        self.encode_result = ""               # Buffer for encoded data
        # ETSI/IEEE 1609.2 encrypted container expects protocolVersion=3 (EA rejects =1)
        self.m_protocolversion = 3            # Protocol version
        self.m_version = 3                    # Data version
        self.m_recipientID = "D41845A1F71C356A" # Recipient ID (8 bytes)
        self.m_hashId = "sha256"              # Hash algorithm (SHA-256)
        self.m_psid = 623                     # PSID (service identifier)
        self.m_itsID = "4472697665580108"     # ITS ID (vehicle/device identifier)
        self.m_certFormat = 1                 # Certificate format
        self.m_hours = 168                    # Duration in hours (7 days)
        self.m_bitmapSspEA = "01C0"           # SSP bitmap for the EA

        self.NONCE_LENGTH = 12
        self.AES_KEY_LENGTH = 16 # AES-128
        self.AES_CCM_TAG_LENGTH = 16
        self.CURVE = ec.SECP256R1()           # P-256 curve
        
        self.path = os.path.abspath(os.path.dirname(__file__))


    def readIniFile(self, id = 0) -> "IniEC":
        """Python translation of C++ ECManager::readIniFile().
        Reads PKI_info.ini using INIReader and returns an IniEC with defaults of "UNKNOWN" like the C++ code.
        - Mirrors case-insensitive lookups
        - Prints an error if the file can't be loaded (ParseError() < 0)
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

        ini = IniEC(
            eaCert1=reader.Get("ECinfo", "eaCert1", "UNKNOWN"),
            eaCert2=reader.Get("ECinfo", "eaCert2", "UNKNOWN"),
            eaCert3=reader.Get("ECinfo", "eaCert3", "UNKNOWN"),
            pk_rfc= credentials.get("public_key_rfc", "UNKNOWN"),
            sk_rfc=credentials.get("private_key_rfc", "UNKNOWN"),
            itsID=credentials.get("itsID", "UNKNOWN"),
            recipientID=reader.Get("ECinfo", "recipientID", "UNKNOWN"),
            bitmapSspEA=reader.Get("ECinfo", "bitmapEA", "UNKNOWN"),
        )
        return ini

    @staticmethod
    def loadCompressedPublicKey(compressed_key: bytes, compression: int):
        
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
            curve = ec.SECP256R1() 
            evp_pkey = ec.EllipticCurvePublicKey.from_encoded_point(curve, pk_data)            
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
            # Ensure the directory exists before writing the file
            dir_path = os.path.dirname(file_name)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            with open(file_name, "wb") as file_out:
                length = len(key)
                file_out.write(length.to_bytes(8, byteorder="little"))  # Write the length (size_t, 8 bytes)
                file_out.write(key.encode("utf-8"))  # Write the string
                print("Pre Shared Key saved to binary file.")
        except OSError as e:
            raise SecurityError(f"Failed to persist pre-shared key to '{file_name}'") from e
    
    def encryptMessage(self, plaintext: bytes, receiverPublicKey: ec.EllipticCurvePublicKey, p1: bytes | None = None, id: int | None = None):
        
        filePath = os.path.join(self.path, 'certificates', 'keys', f'ITS_{id}', "pskEC.bin")
        # 1) Generate random AES key and nonce
        aesKey = os.urandom(self.AES_KEY_LENGTH) # AES-128, 128 bit key
        nonce = os.urandom(self.NONCE_LENGTH) # 12 byte nonce for AES-CCM
        
        # Print and save the AES key (matching C++ behavior)
        aes_key_hex = ''.join(f'{byte:02x}' for byte in aesKey)
        self.saveStringToFile(aes_key_hex, filePath)

        # 2) Encrypt with AES-128-CCM (using aes_key and nonce)
        aead = AESCCM(aesKey, tag_length=self.AES_CCM_TAG_LENGTH)
        ct_and_tag = aead.encrypt(nonce, plaintext, None)
        ciphertext = ct_and_tag[:-self.AES_CCM_TAG_LENGTH]
        aesCcmTag = ct_and_tag[-self.AES_CCM_TAG_LENGTH:]
        
        # 3) Validate receiver's public key and generate ephemeral key for ECDH
        if not isinstance(receiverPublicKey, ec.EllipticCurvePublicKey):
            raise InvalidKey("The recipient's public key is not an EC key or is invalid.")
        # generate ephemeral key
        ephemeralKey = ec.generate_private_key(self.CURVE)
        
        sharedSecret = ephemeralKey.exchange(ec.ECDH(), receiverPublicKey)  # ECDH
        # 4) KDF2(SHA-256) → 48 byte: ke (16) || km (32)
        derivedKey = self.deriveKeyWithKDF2(sharedSecret, p1, 48)
        ke, km = derivedKey[:16], derivedKey[16:]

        # 5) "Encrypt" the AES key with XOR using ke (ECIES style key encapsulation)
        encryptedKey = bytes(a ^ b for a, b in zip(aesKey, ke))

        # 6) HMAC-SHA256(encrypted_key) with km, truncated to 16 bytes
        h = hmac.HMAC(km, hashes.SHA256())
        h.update(encryptedKey)
        full_tag = h.finalize()
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
    # TODO
    def doEncryption(self, message: bytes, encPkEA: GNecdsaNistP256, p1, id: int):

        # Extract and prepare the public key from certificate data
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
        
        # Load the receiver's public key
        receiver_pub_key = self.loadCompressedPublicKey(publicKeyEA, compression)
        
        # Use encryptMessage to perform the encryption
        encryption_result = self.encryptMessage(message, receiver_pub_key, p1, id)
        
        # Convert the result to EncData
        return EncData(
            ciphertextWithTag=encryption_result["ciphertext"] + encryption_result["aesCcmTag"],
            encryptedKey=encryption_result["encrypted_key"],
            ephemeralPublicKey=encryption_result["ephemeral_public_key"],
            x_value=encryption_result["ephemeral_public_key"][1:33],  # Extract x (skip the 0x04 prefix)
            y_value=encryption_result["ephemeral_public_key"][33:],   # Extract y
            eciesTag=encryption_result["ecies_tag"],
            nonce=encryption_result["nonce"]
        )

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

    def loadECKeyFromRFC5480(self, private_key_rfc: str, public_key_rfc: str, password: bytes | None = None):
        try:
            priv_der = bytes.fromhex(private_key_rfc)
        except Exception as e:
            raise SecurityError("Error parsing private key hex string to DER") from e
        try:
            pub_der = bytes.fromhex(public_key_rfc)
        except Exception as e:
            raise SecurityError("Error parsing public key hex string to DER") from e
        try:
            pkey = load_der_private_key(priv_der, password=password)
        except Exception as e:
            raise SecurityError("Error loading private key from PKCS#8 DER") from e
        if not isinstance(pkey, ec.EllipticCurvePrivateKey):
            raise SecurityError("Loaded private key is not an EC key")
        try:
            pub_key = load_der_public_key(pub_der)
        except Exception as e:
            raise SecurityError("Error loading public key from RFC 5480 DER") from e

        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            raise SecurityError("Loaded public key is not an EC key")

        # --- Step 4: verify the curve (typically P-256)
        if not isinstance(pkey.curve, type(self.CURVE)) or not isinstance(pub_key.curve, type(self.CURVE)):
            raise SecurityError("EC curve mismatch or unsupported curve")

        # --- Step 5: ensure the public key matches the private key
        priv_pub_numbers = pkey.public_key().public_numbers()
        loaded_pub_numbers = pub_key.public_numbers()
        if (priv_pub_numbers.x != loaded_pub_numbers.x) or (priv_pub_numbers.y != loaded_pub_numbers.y):
            raise SecurityError("Public key does not match the private key")

        # All good: return the private key (its public component is consistent)
        return pkey


    def recoverECKeyPair(self, ephemeral: bool, id: int | None = None) -> "GNpublicKey":

        public_key = GNpublicKey()

        if ephemeral:
            if id is None:
                raise SecurityConfigurationError("Vehicle id is required to load ephemeral key pair")
            keys_folder = os.path.join(self.path, 'certificates', 'keys', f'ITS_{id}')

            private_key_file = os.path.join(keys_folder, "ephSKEY.pem")
            public_key_file = os.path.join(keys_folder, "ephPKEY.pem")

            ec_key = self.loadECKeyFromFile(private_key_file, public_key_file)
            self.m_EPHecKey = ec_key
        else:
            cr_path = os.path.join(self.path, 'certificates', 'credentials.json')
            credentials = CRRReader(cr_path, id)
            if credentials is None:
                raise SecurityConfigurationError(
                    f"Missing credentials for vehicle '{id}' in '{cr_path}'"
                )

            public_key_rfc = credentials.get("public_key_rfc", "UNKNOWN")
            private_key_rfc = credentials.get("private_key_rfc", "UNKNOWN")

            if (not public_key_rfc) or (not private_key_rfc) or \
               ("UNKNOWN" in public_key_rfc) or ("UNKNOWN" in private_key_rfc):
                raise SecurityConfigurationError("Missing RFC5480 key material in credentials")

            ec_key = self.loadECKeyFromRFC5480(private_key_rfc, public_key_rfc)
            # Store as the primary key
            self.m_ecKey = ec_key

        # Extract the public component and determine the prefix (y parity)
        pub_numbers = ec_key.public_key().public_numbers()

        x_bytes = pub_numbers.x.to_bytes(32, "big")
        y_is_even = (pub_numbers.y % 2) == 0
        prefix_type = 'compressed_y_0' if y_is_even else 'compressed_y_1'  # 0x02 (even y) or 0x03 (odd y)

        # Extract the public component in compressed format
        pub_key = ec_key.public_key()

        # Obtain the compressed key using cryptography
        compressed_point = pub_key.public_bytes(
            Encoding.X962,
            PublicFormat.CompressedPoint
        )

        # The first byte is the prefix (0x02 or 0x03), the next 32 bytes are the x coordinate
        prefix_byte = compressed_point[0]
        x_bytes = compressed_point[1:33]

        prefix_type = 'compressed_y_0' if prefix_byte == 0x02 else 'compressed_y_1'

        public_key.pk = x_bytes
        public_key.prefix = prefix_type
        return public_key

    def signHash(self, hash: bytes, ec_private_key: ec.EllipticCurvePrivateKey) -> dict | None:

        try:
            # Input validation
            if not isinstance(hash, (bytes, bytearray)):
                raise SecurityError("Hash value must be bytes")
            if len(hash) != 32:
                raise SecurityError("Expected a 32-byte SHA-256 digest")

            signature = ec_private_key.sign(hash, ec.ECDSA(Prehashed(hashes.SHA256())))
            return signature
        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError("Error signing hash") from e
    
    def signatureCreation(self, tbsData: bytes, ephemeral: bool) -> GNsignMaterial:

        try:
            signMaterial = GNsignMaterial()
            signIdentifierSelf = b''

            tbsData_hash = self.computeSHA256(tbsData)
            signIDself_hash = self.computeSHA256(signIdentifierSelf)

            concatenatedHashes = tbsData_hash + signIDself_hash
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
            raise SecurityError("Error creating EC signature") from e

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

    def regeneratePEM(self, id) -> None:
        keys_folder = os.path.join(self.path, 'certificates', 'keys', f'ITS_{id}')

        priv_path = os.path.join(keys_folder,"ephSKEY.pem")
        pub_path = os.path.join(keys_folder,"ephPKEY.pem")
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

        print("Key pair generated and saved to ephSKEY.pem and ephPKEY.pem")


    def createRequest(self,id):
        
        ini = self.readIniFile(id)
        
        EAcertificate = ini.eaCert1 + ini.eaCert2 + ini.eaCert3
        binaryCert = bytes.fromhex(EAcertificate)

        # TODO: find a better place to load the ASN.1 certificates
        asn_folder = os.path.join("data", "asn", "security")
        asn_files = glob.glob(os.path.join(asn_folder, "*.asn"))
        if not asn_files:
            raise SecurityConfigurationError(f"No ASN.1 file found in '{asn_folder}'")
        asn1_modules = asn1tools.compile_files(asn_files, 'oer')

        certificate_hash = self.computeSHA256(binaryCert)
        certContent = binaryCert
        certData_decoded = asn1_modules.decode('CertificateBase', certContent)

        new_cert = GNcertificateDC()
        new_cert.version = certData_decoded['version']
        new_cert.type = certData_decoded['type']
        new_cert.issuer = certData_decoded['issuer'][1]
        
        id_present = certData_decoded['toBeSigned']['id'][0]
        if id_present == 'none':
            new_cert.tbs.id = 0
        elif id_present == 'name':
            new_cert.tbs.name = certData_decoded['toBeSigned']['id'][1]

        new_cert.tbs.cracaId = certData_decoded['toBeSigned']['cracaId']
        new_cert.tbs.crlSeries = certData_decoded['toBeSigned']['crlSeries']
        new_cert.tbs.validityPeriod_start = certData_decoded['toBeSigned']['validityPeriod']['start']

        duration = certData_decoded['toBeSigned']['validityPeriod']['duration'][0]
        if duration == 'hours': 
            new_cert.tbs.validityPeriod_duration = certData_decoded['toBeSigned']['validityPeriod']['duration'][1]
        # AppPermissions
        for appPermDecoded in certData_decoded['toBeSigned']['appPermissions']:
            newServ = GNpsidSsp(psid=None, bitmapSsp=None)
            newServ.psid = appPermDecoded['psid']
            service_permission = appPermDecoded.get('ssp', None)
            if service_permission:
                if service_permission[0] == 'bitmapSsp':
                    newServ.bitmapSsp = service_permission[1]
            new_cert.tbs.appPermissions.append(newServ)
          
        new_cert.tbs.symAlgEnc = certData_decoded['toBeSigned']['encryptionKey']['supportedSymmAlg']
        
        public_key = certData_decoded['toBeSigned']['encryptionKey'].get('publicKey', None)
        
        if public_key is not None and public_key[0]=='eciesNistP256':
            eciesNistP256 = public_key[1]
            if eciesNistP256[0] == 'x-only':
                new_cert.tbs.encPublicKey.p256_x_only = eciesNistP256[1]
            elif eciesNistP256[0] == 'fill':
                new_cert.tbs.encPublicKey.p256_fill = None
            elif eciesNistP256[0] == 'compressed-y-0':
                new_cert.tbs.encPublicKey.p256_compressed_y_0 = eciesNistP256[1]
            elif eciesNistP256[0] == 'compressed-y-1':
                new_cert.tbs.encPublicKey.p256_compressed_y_1 = eciesNistP256[1]
            elif eciesNistP256[0] == 'uncompressed':
                new_cert.tbs.encPublicKey.p256_uncompressed_x = eciesNistP256[1]
                new_cert.tbs.encPublicKey.p256_uncompressed_y = eciesNistP256[2]
        # verifyKeyIndicator
        verifyKeyIndicator = certData_decoded['toBeSigned'].get('verifyKeyIndicator', None)
        if verifyKeyIndicator and verifyKeyIndicator[0] == 'verificationKey':
            verificationKey = verifyKeyIndicator[1]
            if verificationKey[0] == 'ecdsaNistP256':
                ecdsaNistP256 = verificationKey[1]
                if ecdsaNistP256[0] == 'x-only':
                    new_cert.tbs.verifyKeyIndicator.p256_x_only = ecdsaNistP256[1]
                elif ecdsaNistP256[0] == 'fill':
                    new_cert.tbs.verifyKeyIndicator.p256_fill = None
                elif ecdsaNistP256[0] == 'compressed-y-0':
                    new_cert.tbs.verifyKeyIndicator.p256_compressed_y_0 = ecdsaNistP256[1]
                elif ecdsaNistP256[0] == 'compressed-y-1':
                    new_cert.tbs.verifyKeyIndicator.p256_compressed_y_1 = ecdsaNistP256[1]
                elif ecdsaNistP256[0] == 'uncompressed':
                    new_cert.tbs.verifyKeyIndicator.p256_uncompressed_x = ecdsaNistP256[1]
                    new_cert.tbs.verifyKeyIndicator.p256_uncompressed_y = ecdsaNistP256[2]
        
        signcertData_decoded = certData_decoded.get('signature', None)
        if signcertData_decoded[0] == 'ecdsaNistP256Signature':
            ecdsaNistP256Signature = signcertData_decoded[1]
            present4 = ecdsaNistP256Signature.get('rSig', None)
            if present4 is not None:
                if present4[0] == 'x-only':
                    new_cert.rSig.p256_x_only = present4[1]
                elif present4[0] == 'fill':
                    new_cert.rSig.p256_fill = None
                elif present4[0] == 'compressed_y_0':
                    new_cert.rSig.p256_compressed_y_0 = present4[1]
                elif present4[0] == 'compressed_y_1':
                    new_cert.rSig.p256_compressed_y_1 = present4[1]
                elif present4[0] == 'uncompressed':
                    new_cert.rSig.p256_uncompressed_x = present4[1]
                    new_cert.rSig.p256_uncompressed_y = present4[2]
            if ecdsaNistP256Signature['sSig'] is not None:
                new_cert.signature_sSig = ecdsaNistP256Signature['sSig']
        
        # Recover the EC key pair
        self.ephemeral = False
        public_key = self.recoverECKeyPair(self.ephemeral, id)
        # Get the ephemeral key pair
        self.ephemeral = True
        EPHpublic_key = self.recoverECKeyPair(self.ephemeral, id)

        m_generationTime = self.getCurrentTimestamp()
        m_generationTime32 = (m_generationTime // 1_000_000) & 0xFFFFFFFF

        # Inner EC request
        innerRequest = {}
        ITS_S_ID = bytes.fromhex(ini.itsID)
        innerRequest['itsId'] = ITS_S_ID
        innerRequest['certificateFormat'] = self.m_certFormat
        
        # Set the verification key
        innerRequest['publicKeys'] = {}
        if EPHpublic_key.prefix == 'compressed_y_0':
            innerRequest['publicKeys']['verificationKey'] = ('ecdsaNistP256', ('compressed-y-0', EPHpublic_key.pk))
        elif EPHpublic_key.prefix == 'compressed_y_1':
            innerRequest['publicKeys']['verificationKey'] = ('ecdsaNistP256', ('compressed-y-1', EPHpublic_key.pk))
        
        # appPermissions
        appPermission = []
        psid1 = {}
        psid1['psid'] = self.m_psid
        servicePermission1 = ('bitmapSsp', bytes.fromhex(ini.bitmapSspEA))
        psid1['ssp'] = servicePermission1
        appPermission.append(psid1)

        # requestedSubjectAttributes: include validityPeriod of 1 hour (ETSI 103 097 / 102 941)
        requested_attrs = {'appPermissions': appPermission}
        validityPeriod_req = {
            'start': m_generationTime32,               # Time32 (TAI). Use 32-bit value to satisfy ASN.1 UINT32
            'duration': ('hours', 168)                   # Request a certificate valid for 1 hour
        }
        requested_attrs['validityPeriod'] = validityPeriod_req

        innerRequest['requestedSubjectAttributes'] = requested_attrs
        request_result = asn1_modules.encode('InnerEcRequest', innerRequest)

        # ---------- EtsiTs1030971Data-Signed ----------------
        ieeeData = {}
        ieeeData['protocolVersion'] = self.m_protocolversion
        contentContainer1 = ['signedData', 'placeholder']
        signData = {}
        signData['hashId'] = self.m_hashId
        tbsOuter = {}
        signPayload = {}
        dataPayload2 = {}
        dataPayload2['protocolVersion'] = self.m_protocolversion
        
        # ---------- EtsiTs102941Data ----------------
        dataContentPayload2 = ['unsecuredData', 'placeholder']
        dataPayload102 = {}
        dataPayload102['version'] = 1
        dataContentPayload102 = ['enrolmentRequest', 'placeholder']

        dataPayload = {}
        dataPayload['protocolVersion'] = self.m_protocolversion
        dataContentPayload = ['signedData', 'placeholder']
        signDataInner = {}
        signDataInner['hashId'] = self.m_hashId
        tbsInner = {}
        signPayloadInner = {}
        dataPayloadInner = {}
        dataPayloadInner['protocolVersion'] = self.m_protocolversion
        dataContentPayloadInner = ('unsecuredData', request_result)
        dataPayloadInner['content'] = dataContentPayloadInner
        #---------- Payload InnerECrequest ----------------
        signPayloadInner['data'] = dataPayloadInner
        tbsInner['payload'] = signPayloadInner

        tbsInner['headerInfo'] = {}
        tbsInner['headerInfo']['psid'] = self.m_psid
        tbsInner['headerInfo']['generationTime'] = m_generationTime
        signDataInner['tbsData'] = tbsInner
        
        tbsInner_encoded = asn1_modules.encode('ToBeSignedData', tbsInner)
        self.ephemeral = True
        signMaterial = self.signatureCreation(tbsInner_encoded, self.ephemeral)
        signDataInner['signer'] = ('self', None)

        signatureContentInner = ['ecdsaNistP256Signature']
        R = signMaterial.r
        S = signMaterial.s
        
        ecdsaNistP256Signature = {
            'rSig': ('x-only', R),
            'sSig': S
        }
        signatureContentInner.append(ecdsaNistP256Signature)
        signDataInner['signature'] = tuple(signatureContentInner)
        # ---------- EtsiTs103097Data-Signed (InnerECManagerSignedForPOP) ----------------
        dataContentPayload[1] = signDataInner
        dataPayload['content'] = tuple(dataContentPayload)
        
        dataContentPayload102[1] = dataPayload
        dataPayload102['content'] = tuple(dataContentPayload102)
        pop_request = asn1_modules.encode('EtsiTs102941Data', dataPayload102)

        dataContentPayload2[1] = pop_request
        dataPayload2['content'] = tuple(dataContentPayload2)
        signPayload['data'] = dataPayload2
        tbsOuter['payload'] = signPayload
        
        tbsOuter['headerInfo'] = {}
        tbsOuter['headerInfo']['psid'] = self.m_psid
        tbsOuter['headerInfo']['generationTime'] = m_generationTime
        signData['tbsData'] = tbsOuter
        # ---------- EtsiTs102941Data ----------------
        tbsOuter_encoded = asn1_modules.encode('ToBeSignedData', tbsOuter)
        self.ephemeral = False
        sign_materialOuter = self.signatureCreation(tbsOuter_encoded, self.ephemeral)
        signData['signer'] = ('self', None)
        signatureContent = ['ecdsaNistP256Signature']

        R_bytes2 = sign_materialOuter.r
        S_bytes2 = sign_materialOuter.s

        ecdsaNistP256Signature = {
            'rSig': ('x-only', R_bytes2),
            'sSig': S_bytes2
        }
        signatureContent.append(ecdsaNistP256Signature)
        signData['signature'] = tuple(signatureContent)
        contentContainer1[1] = signData 
        ieeeData['content'] = tuple(contentContainer1)  # Fixed: use contentContainer1 instead of contentContainer
        
        signedData_result = asn1_modules.encode('Ieee1609Dot2Data', ieeeData)
        dataEnc = self.doEncryption(signedData_result, new_cert.tbs.encPublicKey, certificate_hash, id)
        
        # ---------- DATA ENCRYPTED ENCODING PART ----------------
        ieeeData2 = {}
        ieeeData2['protocolVersion'] = self.m_protocolversion
        contentContainer = ['encryptedData', 'placeholder']

        recipientsSeq = []
        recipInfo = ['certRecipInfo', 'placeholder']
        recipient = bytes.fromhex(ini.recipientID)
        recID = recipient
        recipInfo[1] = {}
        recipInfo[1]['recipientId'] = recID
        recipInfo[1]['encKey'] = ['eciesNistP256', 'placeholder']
        encKey = dataEnc.encryptedKey
        recipInfo[1]['encKey'][1] = {}
        recipInfo[1]['encKey'][1]['c'] = encKey
        eciesTag = dataEnc.eciesTag
        recipInfo[1]['encKey'][1]['t'] = eciesTag
        recipInfo[1]['encKey'][1]['v'] = ['uncompressedP256', {}]
        x_value = dataEnc.x_value
        y_value = dataEnc.y_value
        recipInfo[1]['encKey'][1]['v'][1]['x'] = x_value
        recipInfo[1]['encKey'][1]['v'][1]['y'] = y_value
        recipInfo[1]['encKey'][1]['v'] = tuple(recipInfo[1]['encKey'][1]['v'])
        recipInfo[1]['encKey'] = tuple(recipInfo[1]['encKey'])
        recipInfo = tuple(recipInfo)
        recipientsSeq.append(recipInfo)
        contentContainer[1] = {}
        contentContainer[1]['recipients'] = recipientsSeq
        contentContainer[1]['ciphertext'] = ('aes128ccm', {})
        nonce = dataEnc.nonce
        contentContainer[1]['ciphertext'][1]['nonce'] = nonce
        ciphertextWithTag = dataEnc.ciphertextWithTag
        contentContainer[1]['ciphertext'][1]['ccmCiphertext'] = ciphertextWithTag

        ieeeData2 ['content'] = tuple(contentContainer)
        encode_result = asn1_modules.encode('Ieee1609Dot2Data', ieeeData2)

        # Saving the binary file for the request
        request_dir = os.path.join(self.path, 'certificates', 'requests', f'ITS_{id}')
        request_path = os.path.join(request_dir, 'requestEC.bin')
        try:
            os.makedirs(request_dir, exist_ok=True)
            with open(request_path, "wb") as binary_file:
                binary_file.write(encode_result)
        except OSError as e:
            raise SecurityError(f"Failed to save EC request to '{request_path}'") from e

        # Calculating request ID (16-byte SHA256 hash of the payload)
        hash_obj = hashlib.sha256()
        hash_obj.update(encode_result)
        hash_digest = hash_obj.digest()

        # Outputting the first 16 bytes of the SHA256 hash as the request ID
        req_id = ''.join(f'{b:02x}' for b in hash_digest[:16])
        print(f"[INFO] Request ID: {req_id}")
    
    def sendPOST(self, id):
        request_dir = os.path.join(self.path, 'certificates', 'requests', f'ITS_{id}')
        response_dir = os.path.join(self.path, 'certificates', 'responses', f'ITS_{id}')
        request_path = os.path.join(request_dir, 'requestEC.bin')
        response_path = os.path.join(response_dir, 'responseEC.bin')

        try:
            os.makedirs(request_dir, exist_ok=True)
            os.makedirs(response_dir, exist_ok=True)
        except OSError as e:
            raise SecurityError("Unable to prepare directories for EC request/response exchange") from e

        try:
            with open(request_path, "rb") as f:
                body = f.read()
        except FileNotFoundError as e:
            raise SecurityError(f"EC request payload '{request_path}' not found") from e
        except OSError as e:
            raise SecurityError(f"Unable to read EC request from '{request_path}'") from e

        url = "http://0.atos-ea.l0.c-its-pki.eu/"
        headers = {
            "Content-Type": "application/x-its-request",
            "Accept": "application/x-its-response"
        }

        try:
            resp = requests.post(url, data=body, headers=headers, timeout=15)
            resp.raise_for_status()
        except requests.HTTPError as e:
            status = e.response.status_code if e.response is not None else "unknown"
            body_text = e.response.text if e.response is not None else str(e)
            raise SecurityError(f"EA POST failed with status {status}: {body_text}") from e
        except requests.RequestException as e:
            raise SecurityError("Error during POST request to EA") from e

        try:
            with open(response_path, "wb") as f:
                f.write(resp.content)
        except OSError as e:
            raise SecurityError(f"Unable to write EC response to '{response_path}'") from e

        return response_path
