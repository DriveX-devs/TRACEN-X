import asn1tools
import glob

certificateRaw = bytes.fromhex("800300807c31b827eca616c21083000000000028e2412c8400a8010280012481040301fffc80012581050401ffffff80808223e3e0a259766f5199f3011a4b4dd017faa0af70f81f890bfd289f81b95b13e3808055a5eb116bc84da1788123cb37d0634917e0266ef39025664c53e4ec2dd6993c8de089236829c97c9ca84990dfebb84b09dd010e21eb90f07660f736eda8e0b5")

cert_fields = {
                "version": 3,
                "type": "explicit",
                "issuer": "7c31b827eca616c2",
                "tbs": {
                    "id": 0,
                    "name": "",
                    "cracaId": "000000",
                    "crlSeries": 0,
                    "validityPeriod_start": 685916460,
                    "validityPeriod_duration": 168,
                    "appPermissions": [
                        {
                            "psid": 36,
                            "bitmapSsp": "01fffc"
                        },
                        {
                            "psid": 37,
                            "bitmapSsp": "01ffffff"
                        }
                    ],
                    "symAlgEnc": 0,
                    "encPublicKey": {
                        "p256_x_only": "",
                        "p256_fill": "",
                        "p256_compressed_y_0": "",
                        "p256_compressed_y_1": "",
                        "p256_uncompressed_x": "",
                        "p256_uncompressed_y": ""
                    },
                    "verifyKeyIndicator": {
                        "p256_x_only": "",
                        "p256_fill": "",
                        "p256_compressed_y_0": "23e3e0a259766f5199f3011a4b4dd017faa0af70f81f890bfd289f81b95b13e3",
                        "p256_compressed_y_1": "",
                        "p256_uncompressed_x": "",
                        "p256_uncompressed_y": ""
                    }
                },
                "rSig": {
                    "p256_x_only": "55a5eb116bc84da1788123cb37d0634917e0266ef39025664c53e4ec2dd6993c",
                    "p256_fill": "",
                    "p256_compressed_y_0": "",
                    "p256_compressed_y_1": "",
                    "p256_uncompressed_x": "",
                    "p256_uncompressed_y": ""
                },
                "signature_sSig": "8de089236829c97c9ca84990dfebb84b09dd010e21eb90f07660f736eda8e0b5"
            }

path = '/Users/giuseppe/Desktop/TRACENX/TRACEN-X/data/asn/security'
files = glob.glob(f"{path}/*.asn")
asn1_modules = asn1tools.compile_files(files, 'oer')

certificate = {}
certificate['version'] = cert_fields['version']
certificate['type'] = cert_fields['type']
certificate['issuer'] = ('sha256AndDigest',bytes.fromhex(cert_fields['issuer']))
certificate['toBeSigned'] = {}
certificate['toBeSigned']['id'] = ('none', None)

certificate['toBeSigned']['cracaId'] = bytes.fromhex(cert_fields['tbs']['cracaId'])
certificate['toBeSigned']['crlSeries'] = cert_fields['tbs']['crlSeries']
certificate['toBeSigned']['validityPeriod'] = {}
certificate['toBeSigned']['validityPeriod']['start'] = cert_fields['tbs']['validityPeriod_start']
certificate['toBeSigned']['validityPeriod']['duration'] = ('hours', cert_fields['tbs']['validityPeriod_duration'])
permissions = []
for permission in cert_fields['tbs']['appPermissions']:
    perm = {}
    perm['psid'] = permission['psid']
    perm['ssp'] = ('bitmapSsp', bytes.fromhex(permission['bitmapSsp']))
    permissions.append(perm)
certificate['toBeSigned']['appPermissions'] = permissions

certificate['toBeSigned']['verifyKeyIndicator'] = ('verificationKey', ('ecdsaNistP256', ('compressed-y-0',bytes.fromhex(cert_fields['tbs']['verifyKeyIndicator']['p256_compressed_y_0']))))
signature = ('ecdsaNistP256Signature',{
    'rSig' : ('x-only', bytes.fromhex(cert_fields['rSig']['p256_x_only'])),
    'sSig' : bytes.fromhex(cert_fields['signature_sSig'])
})
certificate['signature'] = signature
encoded_cert = asn1_modules.encode('CertificateBase', certificate)

# is the same?
print(encoded_cert == certificateRaw)  # Truea
