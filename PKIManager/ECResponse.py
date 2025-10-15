import os
import hashlib
import asn1tools
import glob
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key, load_der_public_key,
    load_pem_private_key, load_der_private_key,
    Encoding, PublicFormat
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, Prehashed

from .INIReader import INIReader
from .CRReader import CRRReader
from .utils.exceptions import SecurityError, SecurityConfigurationError
from .utils.security_models import (
    GNcertificateDC,
    GNecdsaNistP256,
    GNpsidSsp,
    GNpublicKey,
    IniEC,
    cPacket,
    response
)

class ECResponse:
    def __init__(self):

        self.dataResponse = None
        self.length = 0

        self.ephemeral = False
        self.m_ecKey = None # EC key for long-term
        self.m_EPHecKey = None # EC key for ephemeral

        self.NONCE_LENGTH = 12
        self.AES_KEY_LENGTH = 16
        self.AES_CCM_TAG_LENGTH = 16
        self.CURVE = ec.SECP256R1()           # P-256 curve
        
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
            dir_path = os.path.dirname(file_name)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)
            with open(file_name, "wb") as file_out:
                length = len(key)
                file_out.write(length.to_bytes(8, byteorder="little"))  # Write the length (size_t, 8 bytes)
                file_out.write(key.encode("utf-8"))  # Write the string
                print("Pre Shared Key saved to binary file.")
        except OSError as e:
            raise SecurityError(f"Error opening file '{file_name}' for writing") from e
    
    def readFileContent(self, filename):
        try:
            with open(filename, 'rb') as file:
                dataResponse = file.read()
                length = len(dataResponse)
                return dataResponse, length
        except FileNotFoundError as e:
            raise SecurityError(f"Response file '{filename}' not found") from e
        except OSError as e:
            raise SecurityError(f"Error reading file content from '{filename}'") from e
    
    @staticmethod
    def loadCompressedPublicKey(compressed_key: bytes, compression: int):
        # Decode the compressed key from hex to bytes
        if len(compressed_key) != 32:
            raise SecurityError("Compressed public key must be 32 bytes long")

        # Add the prefix for compressed_y_0 or compressed_y_1
        if compression == 2:
            pk_data = b'\x02'  # Prefix for even y
        elif compression == 3:
            pk_data = b'\x03'  # Prefix for odd y
        else:
            raise SecurityError("Compression must be 2 or 3 for EC public keys")

        # Append the compressed key bytes after the prefix
        pk_data = pk_data + compressed_key

        # Verify pk_data length is now 33 bytes (1 prefix byte + 32 key bytes)
        if len(pk_data) != 33:
            raise SecurityError("Compressed key with prefix must be exactly 33 bytes")

        # Load the ECC public key from compressed bytes
        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_data)
            return public_key
        except Exception as e:
            raise SecurityError("Failed to convert compressed public key") from e

    @staticmethod
    def loadUncompressedPublicKey(x_bytes: bytes, y_bytes: bytes):
        # Build uncompressed point: 0x04 || X || Y
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            raise SecurityError("Uncompressed coordinates must be 32 bytes each for P-256")
        try:
            pk_data = b'\x04' + x_bytes + y_bytes
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_data)
            return public_key
        except Exception as e:
            raise SecurityError("Failed to convert uncompressed public key") from e
    
    @staticmethod
    def computeSHA256(data: bytes) -> bytes:
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.digest()

    @staticmethod
    def hashed_id8(data: bytes) -> bytes:
        return hashlib.sha256(data).digest()[-8:]

    
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
    
    def doDecryption(self, ciphertextWithTag: bytes, nonce: bytes, id) -> bytes:
        # Always reload the key for the specific ID instead of reusing an existing one
        aesKeyPath = os.path.join(self.path, 'certificates', 'keys',f'ITS_{id}', 'pskEC.bin')
        self.m_aesKey = self.retrieveStringFromFile(aesKeyPath)
        
        if not self.m_aesKey:
            raise SecurityError("Failed to retrieve pre-shared key for EC response decryption")
        
        psk = bytes.fromhex(self.m_aesKey)
        
        decrypted_message = self.decryptMessage(ciphertextWithTag, nonce, psk)
        return decrypted_message
        
    def loadECKeyFromFile(self, private_key_file: str, public_key_file: str, password: bytes | None = None):

        try:
            with open(private_key_file, 'rb') as f:
                priv_bytes = f.read()
        except OSError as e:
            raise SecurityError(f"Unable to open private key file '{private_key_file}'") from e

        try:
            priv_key = load_pem_private_key(priv_bytes, password=password)
        except Exception as e:
            raise SecurityError(f"Unable to read private key from '{private_key_file}'") from e

        if not isinstance(priv_key, ec.EllipticCurvePrivateKey):
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

        if not isinstance(priv_key.curve, type(self.CURVE)) or not isinstance(pub_key.curve, type(self.CURVE)):
            raise SecurityError("EC curve mismatch or unsupported curve")

        priv_pub_numbers = priv_key.public_key().public_numbers()
        loaded_pub_numbers = pub_key.public_numbers()
        if (priv_pub_numbers.x != loaded_pub_numbers.x) or (priv_pub_numbers.y != loaded_pub_numbers.y):
            raise SecurityError("Public key does not match the private key")

        return priv_key
    
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
            priv_key = load_der_private_key(priv_der, password=password)
        except Exception as e:
            raise SecurityError("Error loading private key from PKCS#8 DER") from e
        if not isinstance(priv_key, ec.EllipticCurvePrivateKey):
            raise SecurityError("Loaded private key is not an EC key")
        try:
            pub_key = load_der_public_key(pub_der)
        except Exception as e:
            raise SecurityError("Error loading public key from RFC 5480 DER") from e
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            raise SecurityError("Loaded public key is not an EC key")

        if not isinstance(priv_key.curve, type(self.CURVE)) or not isinstance(pub_key.curve, type(self.CURVE)):
            raise SecurityError("EC curve mismatch or unsupported curve")

        priv_pub_numbers = priv_key.public_key().public_numbers()
        loaded_pub_numbers = pub_key.public_numbers()
        if (priv_pub_numbers.x != loaded_pub_numbers.x) or (priv_pub_numbers.y != loaded_pub_numbers.y):
            raise SecurityError("Public key does not match the private key")

        return priv_key
    

    def reconverECKeyPair(self, ephemeral: bool, id: int) -> GNpublicKey:
        try:
            if ephemeral:
                keysFolder = os.path.join(self.path, 'certificates', 'keys', f'ITS_{id}')
                private_key_file = os.path.join(keysFolder, 'ephSKEY.pem')
                public_key_file = os.path.join(keysFolder, 'ephPKEY.pem')
                ec_key = self.loadECKeyFromFile(private_key_file, public_key_file)
                self.m_EPHecKey = ec_key
            else:
                if not self.pk_rfc or not self.sk_rfc or "UNKNOWN" in (self.pk_rfc + self.sk_rfc):
                    raise SecurityConfigurationError("Missing RFC5480 key material for EC response")
                ec_key = self.loadECKeyFromRFC5480(self.sk_rfc, self.pk_rfc)
                self.m_ecKey = ec_key

            compressed_bytes = ec_key.public_key().public_bytes(
                encoding=Encoding.X962,
                format=PublicFormat.CompressedPoint
            )
            prefix_byte = compressed_bytes[0]
            if prefix_byte == 0x02:
                prefix_type = "compressed_y_0"
            elif prefix_byte == 0x03:
                prefix_type = "compressed_y_1"
            else:
                raise SecurityError("Unexpected prefix while encoding EC public key")

            return GNpublicKey(pk=compressed_bytes[1:], prefix=prefix_type)
        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError("Error recovering EC key pair") from e

    def signatureVerification(self, tbsData: bytes, rValue: GNecdsaNistP256, sValue: str, verifyKeyIndicator: GNecdsaNistP256) -> bool:
        # Select the EA public key preferring usable forms (compressed or uncompressed)
        EAPublicKey = None
        if verifyKeyIndicator.p256_compressed_y_0:
            EAPublicKey = self.loadCompressedPublicKey(verifyKeyIndicator.p256_compressed_y_0, 2)
        elif verifyKeyIndicator.p256_compressed_y_1:
            EAPublicKey = self.loadCompressedPublicKey(verifyKeyIndicator.p256_compressed_y_1, 3)
        elif verifyKeyIndicator.p256_uncompressed_x and verifyKeyIndicator.p256_uncompressed_y:
            EAPublicKey = self.loadUncompressedPublicKey(
                verifyKeyIndicator.p256_uncompressed_x,
                verifyKeyIndicator.p256_uncompressed_y
            )
        elif verifyKeyIndicator.p256_x_only:
            raise SecurityError(
                "verifyKeyIndicator contains only x-only data; cannot reconstruct public key"
            )
        else:
            raise SecurityError("verifyKeyIndicator does not contain a usable public key")

        if EAPublicKey is None:
            raise SecurityError("Failed to load EA public key for signature verification")

        signID = self.signSelf
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
            raise SecurityError("EC signature verification failed") from e
    
    def readIniFile(self, id) -> "IniEC":
        
        ini_path = os.path.join(self.path, 'certificates', 'PKI_info.ini')
        credentials_path = os.path.join(self.path, 'certificates', 'credentials.json')

        reader = INIReader(ini_path)
        if reader.ParseError() < 0:
            raise SecurityConfigurationError(f"Can't load '{ini_path}'")

        credentials = CRRReader(credentials_path, id)
        if credentials is None:
            raise SecurityConfigurationError(
                f"Missing credentials for vehicle '{id}' in '{credentials_path}'"
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

        self.signSelf = bytes.fromhex(ini.eaCert1 + ini.eaCert2 + ini.eaCert3)
        self.pk_rfc = ini.pk_rfc
        self.sk_rfc = ini.sk_rfc
        self.itsID = ini.itsID

        return ini

    
    def getECResponse(self,id):

        asn_folder = os.path.join("data", "asn", "security")
        asn_files = glob.glob(os.path.join(asn_folder, "*.asn"))
        if not asn_files:
            raise SecurityConfigurationError(f"No ASN.1 file found in '{asn_folder}'")
        asn1_modules = asn1tools.compile_files(asn_files, 'oer')

        ini = self.readIniFile(id)
        if ini is None:
            raise RuntimeError(
                f"Unable to generate EC response because credentials for vehicle '{id}' are missing"
            )

        binaryCert = self.signSelf
        certificate_hash = self.computeSHA256(binaryCert)
        
        certContent = binaryCert

        certData_decoded = asn1_modules.decode('CertificateBase', certContent)

        newCert = GNcertificateDC()
        newCert.version = certData_decoded['version']
        newCert.type = certData_decoded['type']
        newCert.issuer = certData_decoded['issuer'][1]

        id_present =  certData_decoded['toBeSigned']['id'][0]
        if id_present == 'none':
            newCert.tbs.id = 0
        elif id_present == 'name':
            newCert.tbs.name = certData_decoded['toBeSigned']['id'][1]
        
        newCert.tbs.cracaId = certData_decoded['toBeSigned']['cracaId']
        newCert.tbs.crlSeries = certData_decoded['toBeSigned']['crlSeries']
        newCert.tbs.validityPeriod_start = certData_decoded['toBeSigned']['validityPeriod']['start']

        duration = certData_decoded['toBeSigned']['validityPeriod']['duration'][0]
        
        if duration == 'years': # asn1tools decodes this value using years instead of hours
            newCert.tbs.validityPeriod_duration = certData_decoded['toBeSigned']['validityPeriod']['duration'][1]
        # AppPermissions
        for perm in certData_decoded['toBeSigned']['appPermissions']:
            newServ = GNpsidSsp(psid=None, bitmapSsp=None)
            newServ.psid = perm['psid']
            if perm['ssp'] is not None:
                if perm['ssp'][0] == 'bitmapSsp':
                    newServ.bitmapSsp = perm['ssp'][1]
            newCert.tbs.appPermissions.append(newServ)
        
        newCert.tbs.symAlgEnc = certData_decoded['toBeSigned']['encryptionKey']['supportedSymmAlg']
        
        if certData_decoded['toBeSigned']['encryptionKey']['publicKey'][0]=='eciesNistP256':
            
            if certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][0] == 'x-only':
                newCert.tbs.encPublicKey.p256_x_only = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
            elif certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][0] == 'fill':
                newCert.tbs.encPublicKey.p256_fill = None
            elif certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][0] == 'compressed-y-0':
                newCert.tbs.encPublicKey.p256_compressed_y_0 = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
            elif certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][0] == 'compressed-y-1':
                newCert.tbs.encPublicKey.p256_compressed_y_1 = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
            elif certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][0] == 'uncompressed':
                newCert.tbs.encPublicKey.p256_uncompressed_x = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][1]
                newCert.tbs.encPublicKey.p256_uncompressed_y = certData_decoded['toBeSigned']['encryptionKey']['publicKey'][1][2]
        
        if certData_decoded['toBeSigned']['verifyKeyIndicator'][0] == 'verificationKey':
            if certData_decoded['toBeSigned']['verifyKeyIndicator'][1][0] == 'ecdsaNistP256': 
                if certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][0] == 'x-only':
                    newCert.tbs.verifyKeyIndicator.p256_x_only = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                elif certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][0] == 'fill':
                    newCert.tbs.verifyKeyIndicator.p256_fill = None
                elif certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][0] == 'compressed-y-0':
                    newCert.tbs.verifyKeyIndicator.p256_compressed_y_0 = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                elif certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][0] == 'compressed-y-1':
                    newCert.tbs.verifyKeyIndicator.p256_compressed_y_1 = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                elif certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][0] == 'uncompressed':
                    newCert.tbs.verifyKeyIndicator.p256_uncompressed_x = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                    newCert.tbs.verifyKeyIndicator.p256_uncompressed_y = certData_decoded['toBeSigned']['verifyKeyIndicator'][1][1][2]
            
        signcertData_decoded = certData_decoded['signature']
        if signcertData_decoded[0] == 'ecdsaNistP256Signature':
            present4 = signcertData_decoded[1]['rSig'][0]
            if present4 == 'x-only':
                newCert.rSig.p256_x_only = signcertData_decoded[1]['rSig'][1]
            elif present4 == 'fill':
                newCert.rSig.p256_fill = None
            elif present4 == 'compressed-y-0':
                newCert.rSig.p256_compressed_y_0 = signcertData_decoded[1]['rSig'][1]
            elif present4 == 'compressed-y-1':
                newCert.rSig.p256_compressed_y_1 = signcertData_decoded[1]['rSig'][1]
            elif present4 == 'uncompressed':
                newCert.rSig.p256_uncompressed_x = signcertData_decoded[1]['rSig'][1]
                newCert.rSig.p256_uncompressed_y = signcertData_decoded[1]['rSig'][2]
            newCert.signature_sSig = signcertData_decoded[1]['sSig']
        
        RPath = os.path.join(self.path, 'certificates', 'responses', f'ITS_{id}', 'responseEC.bin')
        dataResponse, length = self.readFileContent(RPath)
        if length == 0:
            raise SecurityError(f"EC response file '{RPath}' is empty")
        
        public_key = self.reconverECKeyPair(self.ephemeral, id)
        packetContent = dataResponse

        encPacket = cPacket()

        ieeeData_decoded = asn1_modules.decode('Ieee1609Dot2Data', packetContent)
        encPacket.m_protocolversion = ieeeData_decoded['protocolVersion']

        contentDecoded = ieeeData_decoded['content']
        # check the present, here is always signed data
        present1 = contentDecoded[0]
        if present1 == 'encryptedData':
            
            encDataDec = contentDecoded[1]
            for recipient in encDataDec['recipients']:
                present3 = recipient[0]
                if present3 == 'pskRecipInfo':
                    encPacket.content.encrData.recipient = recipient[1]
            # cipher part

            present6 = encDataDec['ciphertext'][0]
            if present6 == 'aes128ccm':
                encPacket.content.encrData.nonce = encDataDec['ciphertext'][1]['nonce']
                encPacket.content.encrData.ciphertext = encDataDec['ciphertext'][1]['ccmCiphertext']
        
        encPacket.content.unsecuredData = self.doDecryption(encPacket.content.encrData.ciphertext,encPacket.content.encrData.nonce, id)
        if not encPacket.content.unsecuredData:
            raise SecurityError("Decrypted EC payload is empty")
        
        signedDataDecoded = asn1_modules.decode('Ieee1609Dot2Data',encPacket.content.unsecuredData)

        sPack = cPacket()
        sPack.m_protocolversion = signedDataDecoded['protocolVersion']
        contentDecoded2 = signedDataDecoded['content']

        present7 = contentDecoded2[0]
        if present7 == 'signedData':
            signDec = contentDecoded2[1]
            # First signed data field, HASH ID
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
            if present3 == 'digest':
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

                # Ensure the signer digest matches the HashedId8 of the EA certificate in use
                signer_hid8 = sPack.content.signData.signer_digest
                ea_cert_hid8 = self.hashed_id8(binaryCert)
                if signer_hid8 != ea_cert_hid8:
                    raise SecurityError("Signer digest does not match EA certificate HashedId8")

            tbs_hex = asn1_modules.encode('ToBeSignedData', tbsDecoded)
            signValidation = self.signatureVerification(tbs_hex, sPack.content.signData.rSig, sPack.content.signData.signature_sSig, newCert.tbs.verifyKeyIndicator)

        if signValidation:
            etsiData = asn1_modules.decode('EtsiTs102941Data', sPack.content.signData.tbsdata.unsecuredData)
            etsiVersion = etsiData['version']
            etsiContent = etsiData['content']
            
            pres = etsiContent[0]
            if pres == 'enrolmentResponse':
                res = etsiContent[1]
                ECres = response()

                ECres.requestHash = res['requestHash']
                resp_code = res['responseCode']
                ECres.response_code = resp_code 
                is_ok = (resp_code == 'ok') or (resp_code == 0)
                if not is_ok:
                    raise SecurityError(f"EC response returned error code: {resp_code}")

                certDecoded = res['certificate']
                ECres.certificate.version = certDecoded['version']
                ECres.certificate.type = certDecoded['type']
                present11 = certDecoded['issuer'][0]

                if present11 == 'sha256AndDigest':
                    ECres.certificate.issuer = certDecoded['issuer'][1]
                if certDecoded['toBeSigned']['id'][0] == 'none':
                    ECres.certificate.tbs.id = 0
                elif certDecoded['toBeSigned']['id'][0] == 'name':
                    ECres.certificate.tbs.name = certDecoded['toBeSigned']['id'][1]
                ECres.certificate.tbs.cracaId = certDecoded['toBeSigned']['cracaId']
                ECres.certificate.tbs.crlSeries = certDecoded['toBeSigned']['crlSeries']
                ECres.certificate.tbs.validityPeriod_start = certDecoded['toBeSigned']['validityPeriod']['start']
                duration = certDecoded['toBeSigned']['validityPeriod']['duration'][0]
                
                if duration == 'hours':
                    ECres.certificate.tbs.validityPeriod_duration = certDecoded['toBeSigned']['validityPeriod']['duration'][1]
                
                for perm in certDecoded['toBeSigned']['appPermissions']:
                    newServ = GNpsidSsp(psid=None, bitmapSsp=None)
                    newServ.psid = perm['psid']
                    servicePermission = perm['ssp']
                    if servicePermission[0] == 'bitmapSsp':
                        newServ.bitmapSsp = servicePermission[1]
                    ECres.certificate.tbs.appPermissions.append(newServ)
                if certDecoded['toBeSigned']['verifyKeyIndicator'][0] == 'verificationKey':
                    if certDecoded['toBeSigned']['verifyKeyIndicator'][1][0] == 'ecdsaNistP256':
                        if certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][0] == 'x-only':
                            ECres.certificate.tbs.verifyKeyIndicator.p256_x_only = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                        elif certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][0] == 'fill':
                            ECres.certificate.tbs.verifyKeyIndicator.p256_fill = None
                        elif certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][0] == 'compressed-y-0':
                            ECres.certificate.tbs.verifyKeyIndicator.p256_compressed_y_0 = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                        elif certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][0] == 'compressed-y-1':
                            ECres.certificate.tbs.verifyKeyIndicator.p256_compressed_y_1 = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                        elif certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][0] == 'uncompressed':
                            ECres.certificate.tbs.verifyKeyIndicator.p256_uncompressed_x = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][1]
                            ECres.certificate.tbs.verifyKeyIndicator.p256_uncompressed_y = certDecoded['toBeSigned']['verifyKeyIndicator'][1][1][2]
                    
                signCertDecoded = certDecoded['signature']
                if signCertDecoded[0] == 'ecdsaNistP256Signature':
                    present12 = signCertDecoded[1]['rSig'][0]
                    if present12 == 'x-only':
                        ECres.certificate.rSig.p256_x_only = signCertDecoded[1]['rSig'][1]
                    elif present12 == 'fill':
                        ECres.certificate.rSig.p256_fill = None
                    elif present12 == 'compressed-y-0':
                        ECres.certificate.rSig.p256_compressed_y_0 = signCertDecoded[1]['rSig'][1]
                    elif present12 == 'compressed-y-1':
                        ECres.certificate.rSig.p256_compressed_y_1 = signCertDecoded[1]['rSig'][1]
                    elif present12 == 'uncompressed':
                        ECres.certificate.rSig.p256_uncompressed_x = signCertDecoded[1]['rSig'][1]
                        ECres.certificate.rSig.p256_uncompressed_y = signCertDecoded[1]['rSig'][2]
                    ECres.certificate.signature_sSig = signCertDecoded[1]['sSig']

                ec_hex = asn1_modules.encode('CertificateBase',certDecoded)
                self.m_ecBytesStr = ec_hex
                # Save the certificate and expiration date to the file
                CPath = os.path.join(self.path, 'certificates','certificates.json')

                certDict = {
                    str(id): {
                        'EC' :{
                        "itsID" : self.itsID,
                        "certificate": ec_hex.hex(),
                        "start": ECres.certificate.tbs.validityPeriod_start,
                        "end": ECres.certificate.tbs.validityPeriod_start + ECres.certificate.tbs.validityPeriod_duration * 3600
                        }
                    }
                }
                try:
                    if os.path.exists(CPath):
                        with open(CPath, 'r') as f:
                            existing_data = json.load(f)
                    else:
                        existing_data = {}
                    existing_data.update(certDict)
                    with open(CPath, 'w') as f:
                        json.dump(existing_data, f, indent=4)
                except OSError as e:
                    raise SecurityError(f"Error saving certificate data to {CPath}") from e
                except json.JSONDecodeError as e:
                    raise SecurityError(f"Invalid JSON in certificate store '{CPath}'") from e

                return ECres.certificate
        else:
            raise SecurityError("EC response signature is not valid")
