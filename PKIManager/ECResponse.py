import os
import hashlib
import asn1tools
import sys
import glob
import json

from dataclasses import dataclass, field
from typing import List
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
from dataclasses import dataclass

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
class GNpsidSsp:
    psid: int
    bitmapSsp: str

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
class GNpublicKey:
    pk: bytes = b""
    prefix: str = ""

@dataclass
class eData:
    recipient: str = ""
    nonce: str = ""
    ciphertext: str = ""

@dataclass 
class tbsDataSigned:
    protocolversion: int = 0
    unsecuredData: str = ""
    header_psid: int = 0
    header_generationTime: int = 0

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
        self.CURVE = ec.SECP256R1()           # Curva P-256
        
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
            # Ensure the directory exists before writing the file
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
                dataResponse = file.read()
                length = len(dataResponse)
                return dataResponse, length
        except Exception as e:
            print(f"Error reading file content: {e}")
            return None, 0
    
    @staticmethod
    def loadCompressedPublicKey(compressed_key: bytes, compression: int):
        # Decodifica la chiave compressa da esadecimale a bytes
        if len(compressed_key) != 32:
            print("La chiave compressa deve essere di 32 byte")
            return None

        # Aggiunge il prefisso per compressed_y_0 o compressed_y_1
        if compression == 2:
            pk_data = b'\x02'  # Prefisso per y pari
        elif compression == 3:
            pk_data = b'\x03'  # Prefisso per y dispari
        else:
            print("Compression deve essere 2 o 3")
            return None

        # Aggiunge il contenuto di compressed_key_hex dopo il prefisso
        pk_data = pk_data + compressed_key

        # Verifica della lunghezza di pk_data ora dovrebbe essere 33 byte (1 byte di prefisso + 32 byte della chiave)
        if len(pk_data) != 33:
            print("La chiave compressa con prefisso non ha la lunghezza corretta (33 byte).")
            return None

        # Carica la chiave pubblica ECC da bytes compressi
        try:
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_data)
            return public_key
        except Exception as e:
            print(f"Errore nella conversione della chiave pubblica compressa in EC_POINT: {e}")
            return None

    @staticmethod
    def loadUncompressedPublicKey(x_bytes: bytes, y_bytes: bytes):
        # Build uncompressed point: 0x04 || X || Y
        if len(x_bytes) != 32 or len(y_bytes) != 32:
            print("Uncompressed coordinates must be 32 bytes each for P-256")
            return None
        try:
            pk_data = b'\x04' + x_bytes + y_bytes
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk_data)
            return public_key
        except Exception as e:
            print(f"Errore nella conversione della chiave pubblica uncompressed in EC_POINT: {e}")
            return None
    
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
        # Ricarica SEMPRE la chiave per l'ID specifico, invece di riutilizzare 
        # una chiave precedentemente caricata
        aesKeyPath = os.path.join(self.path, 'certificates', 'keys',f'ITS_{id}', 'pskEC.bin')
        self.m_aesKey = self.retrieveStringFromFile(aesKeyPath)
        
        if self.m_aesKey is None:
            raise ValueError("Failed to retrieve pre-shared key from file")
        
        psk = bytes.fromhex(self.m_aesKey)
        
        decrypted_message = self.decryptMessage(ciphertextWithTag, nonce, psk)
        return decrypted_message
        
    def loadECKeyFromFile(self, private_key_file: str, public_key_file: str, password: bytes | None = None):
    
        try:
            # Leggi i bytes dei file
            with open(private_key_file, 'rb') as f:
                priv_bytes = f.read()
        except Exception as e:
            print("Error opening file to load private key", file=sys.stderr)
            self.print_error(e)
            return None
        # Prova a caricare la chiave privata sia come PEM che come DER
        priv_key = None
        try:
            priv_key = load_pem_private_key(priv_bytes, password=password)
        except Exception as e:
            print("Error reading private key from file", file=sys.stderr)
            return None

        if not isinstance(priv_key, ec.EllipticCurvePrivateKey):
            print("Loaded private key is not an EC key", file=sys.stderr)
            return None
        try:
            with open(public_key_file, 'rb') as f:
                pub_bytes = f.read()
        except Exception as e:
            print("Error opening file to load public key", file=sys.stderr)
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

        # Verifica che la curva sia quella attesa (di solito P-256)
        if not isinstance(priv_key.curve, type(self.CURVE)) or not isinstance(pub_key.curve, type(self.CURVE)):
            print("EC curve mismatch or unsupported curve", file=sys.stderr)
            return None

        priv_pub_numbers = priv_key.public_key().public_numbers()
        loaded_pub_numbers = pub_key.public_numbers()
        if (priv_pub_numbers.x != loaded_pub_numbers.x) or (priv_pub_numbers.y != loaded_pub_numbers.y):
            print("Public key does not match the private key", file=sys.stderr)
            return None
        
        return priv_key
    
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
    

    def reconverECKeyPair(self, ephemeral: bool, id: int) -> GNpublicKey:
        ec_key = None
        try:
            if ephemeral:
                keysFolder = os.path.join(self.path, 'certificates', 'keys', f'ITS_{id}')
                private_key_file = os.path.join(keysFolder, 'ephSKEY.pem')
                public_key_file = os.path.join(keysFolder, 'ephPKEY.pem')
                ec_key = self.loadECKeyFromFile(private_key_file, public_key_file)
                
                if ec_key is None:
                    return GNpublicKey()  # Empty instance
                self.m_EPHecKey = ec_key

            else:
                public_key_rfc = self.pk_rfc
                private_key_rfc = self.sk_rfc
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

    def signatureVerification(self, tbsData: bytes, rValue: GNecdsaNistP256, sValue: str, verifyKeyIndicator: GNecdsaNistP256) -> bool:
        # Selezione della chiave pubblica dell'EA: preferisci forme utilizzabili (compressed/uncompressed)
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
            # x-only non è sufficiente per ricostruire la chiave pubblica (manca la parità di y)
            print("verifyKeyIndicator contiene solo x-only: impossibile ricostruire la chiave pubblica per la verifica.")
            return False
        else:
            print("verifyKeyIndicator non contiene una chiave pubblica utilizzabile.")
            return False

        if EAPublicKey is None:
            print("Failed to load the public key!")
            return False        

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
            print("EC Signature is invalid")
            return False
    
    def readIniFile(self, id) -> "IniEC":
        
        ini_path = os.path.join(self.path, 'certificates', 'PKI_info.ini')
        credentials = os.path.join(self.path, 'certificates', 'credentials.json')
        
        reader = INIReader(ini_path)
        if reader.ParseError() < 0:
            print(f"[ERR] Can't load '{ini_path}'")
        credentials = CRRReader(credentials, id)
        if credentials is None:
            print(f"[ERR] Can't load credentials from '{credentials}'", file=sys.stderr)
            return None

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
        asn1_modules = asn1tools.compile_files(asn_files, 'oer')

        ini = self.readIniFile(id)

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
        
        if duration == 'years': # nel decode di asn1tools non è in hours ma in years
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
        if dataResponse is None or length == 0:
            print("[ERR] Error reading the file")
        
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
            print("[ERR] Error decrypting the message")
            return None  
        
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

                # Verifica che il signer digest corrisponda all'HashedId8 del certificato EA usato
                signer_hid8 = sPack.content.signData.signer_digest
                ea_cert_hid8 = self.hashed_id8(binaryCert)
                if signer_hid8 != ea_cert_hid8:
                    print("[ERR] Signer digest non corrisponde all'HashedId8 del certificato EA.")
                    return None

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
                    print(f"[ERR] Response code: {resp_code}")
                    return None

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
                # bisogna salvare nel file il certificato e la data di scadenza
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
                    print(f"Certificate data saved to {CPath}")
                except Exception as e:
                    print(f"Error saving certificate data to {CPath}: {e}")

                return ECres.certificate
        else:
            print("[ERR] Error - signature not valid")
            return None
# Example usage

if __name__ == "__main__":
    path = '/Users/giuseppe/Desktop/TRACEN-x/pkiReqRes/responseEC.bin'
    ec_response = ECResponse()
    ec_response.ephemeral = False
    certificate = ec_response.getECResponse()
    print(ec_response.m_ecBytesStr.hex())
    if certificate:
        print("Certificate retrieved successfully:")
    else:
        print("Failed to retrieve certificate.")