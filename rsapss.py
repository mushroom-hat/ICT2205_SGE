import base64
import hashlib
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
# Create the PKCS#7 signature
from OpenSSL.crypto import PKCS7, X509
from OpenSSL.crypto import FILETYPE_PEM

# Load the RSA private key

from OpenSSL import crypto


def sign():
    with open("cert.pem", "rb") as cert_file:
        cert_buf = cert_file.read()

    with open("key.pem", "rb") as key_file:
        key_buf = key_file.read()

    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key_buf)
    signcert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_buf)

    bio_in = crypto._new_mem_buf("123".encode())
    PKCS7_NOSIGS = 0x4  # defined in pkcs7.h
    pkcs7 = crypto._lib.PKCS7_sign(signcert._x509, pkey._pkey, crypto._ffi.NULL, bio_in, PKCS7_NOSIGS)  # noqa
    bio_out = crypto._new_mem_buf()
    crypto._lib.i2d_PKCS7_bio(bio_out, pkcs7)
    sigbytes = crypto._bio_to_string(bio_out)
    signed_data = base64.b64encode(sigbytes)
    print(signed_data)

    return signed_data

def verify(sig):
    # Load the certificate from file
    with open("cert.pem", "rb") as cert_file:
        cert_buf = cert_file.read()

    # Load the signed data from file or as a string
    signed_data = sig  # Replace with the signed data

    signcert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_buf)
    bio_in = crypto._new_mem_buf("123".encode())
    pkcs7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, base64.b64decode(signed_data))

    store = crypto.X509Store()
    store.add_cert(signcert)
    store_ctx = crypto.X509StoreContext(store, signcert)
    pkcs7_ptr = crypto._ffi.cast("PKCS7 *", pkcs7._pkcs7)

    verified = crypto._lib.PKCS7_verify(pkcs7_ptr, crypto._ffi.NULL, store._store, bio_in, crypto._ffi.NULL,
                                        crypto._lib.PKCS7_NOVERIFY)  # noqa

    if verified == 1:
        print("Signature is valid.")
    else:
        print("Signature is not valid.")


def main():
    sig = sign()
    verify(sig)

if __name__ == "__main__":
    main()