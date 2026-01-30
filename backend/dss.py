from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import binascii


def generate_dss_keys():
    key = DSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def dss_sign(data: bytes, private_key_pem: bytes) -> str:
    try:
        key = DSA.import_key(private_key_pem)
        h = SHA256.new(data)
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(h)
        return binascii.hexlify(signature).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Помилка підпису: {str(e)}")


def dss_verify(data: bytes, signature_hex: str, public_key_pem: bytes) -> bool:
    try:
        key = DSA.import_key(public_key_pem)
        h = SHA256.new(data)
        verifier = DSS.new(key, 'fips-186-3')

        signature = binascii.unhexlify(signature_hex.strip())
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError, binascii.Error):
        return False