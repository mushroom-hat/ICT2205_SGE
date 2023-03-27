import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import serialization, asymmetric, padding

def sign_data(data, private_key_file_path, cert_file_path):
    # Load the private key from file
    with open(private_key_file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # Load the certificate from file
    with open(cert_file_path, "rb") as cert_file:
        cert = load_pem_x509_certificate(cert_file.read())

    # Sign the data using RSA-PSS
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.AsymmetricPadding(),
        hashes.SHA256()
    )

    # Create a PKCS#7 signed data object
    signed_data = asymmetric.load_pem_private_key(
        private_key_file_path.read(),
        password=None,
    )
    signed_data = signed_data.sign(
        signature,
        asymmetric.padding.PKCS7(),
        asymmetric.utils.Prehashed(hashes.SHA256())
    )

    # Return the base64-encoded signed data
    return base64.b64encode(signed_data).decode()

def verify_signature(signed_data, cert_file_path):
    # Load the certificate from file
    with open(cert_file_path, "rb") as cert_file:
        cert = load_pem_x509_certificate(cert_file.read())

    # Decode the base64-encoded signed data
    signed_data = base64.b64decode(signed_data)

    # Verify the PKCS#7 signed data object
    try:
        cert.public_key().verify(
            signed_data,
            None,
            asymmetric.padding.PKCS7(),
            asymmetric.utils.Prehashed(hashes.SHA256())
        )
        print("Signature is valid.")
    except:
        print("Signature is not valid.")

# Example usage:
data = "Hello, world!"
private_key_file_path = "key.pem"
cert_file_path = "cert.pem"

# Sign the data
signed_data = sign_data(data, private_key_file_path, cert_file_path)
print("Signed data:", signed_data)

# Verify the signature
verify_signature(signed_data, cert_file_path)