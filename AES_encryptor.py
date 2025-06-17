from Crypto.Cipher import AES
import os


def pad(data):
    padding_length = 16 - len(data) % 16
    padding = bytes([padding_length] * padding_length)
    return data + padding


def unpad(data):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("błąd padowania")
    return data[:-padding_length]


def encrypt_file(input_file, output_file):
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        padded_plaintext = pad(plaintext)
        ciphertext = cipher.encrypt(padded_plaintext)
        with open(output_file, 'wb') as f:
            f.write(iv + ciphertext)
        encoded_key = key.hex()
        encoded_iv = iv.hex()
        return encoded_key, encoded_iv
    except Exception as e:
        print(f"błąd: : {e}")
        return None, None


def decrypt_file(key, iv, input_file, output_file):
    try:
        decoded_key = bytes.fromhex(key)
        iv_bytes = bytes.fromhex(iv)
        if len(decoded_key) != 32:
            raise ValueError("zły klucz")

        with open(input_file, 'rb') as f:
            file_iv = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(decoded_key, AES.MODE_CBC, file_iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext))

        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
    except Exception as e:
        print(f"bląd: {e}")


if __name__ == "__main__":
    input_file = "test.txt"
    encrypted_file = "Encrypted_HelloWorld"
    decrypted_file = "Decrypted_HelloWorld.txt"

    key, iv = encrypt_file(input_file, encrypted_file)
    if key and iv:
        print("Klucz:", key)
        print("IV:", iv)


        decrypt_file(key, iv, encrypted_file, decrypted_file)


        with open(input_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
            if f1.read() == f2.read():
                print("pliki przed i po są zgodne!")
            else:
                print("błąd w szyfrowaniu bądź deszyfrowaniu")
    else:
        print("szyfrowanie się nie powiodło")