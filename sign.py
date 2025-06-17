from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import os


# Key Generation
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_file(private_key, file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, file_path, signature):
    with open(file_path, 'rb') as f:
        data = f.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


if __name__ == "__main__":
    private_key, public_key = generate_keys()

    file_to_sign = input("Podaj dokument do podpisu")


    signature = sign_file(private_key, file_to_sign)

    with open("signature.sig", "wb") as f:
        f.write(signature)

    with open("signature.sig", "rb") as f:
        stored_signature = f.read()

    is_valid = verify_signature(public_key, file_to_sign, stored_signature)
