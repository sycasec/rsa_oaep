from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15

# from Crypto.Hash import SHA256, SHA512


def generate_key_pair(
    pk_format,
    pb_format,
    bits=2048,
    passphrase=None,
    pkcs=1,
    cipher="AES256-CBC",
    hash="SHA512",
):
    key = RSA.generate(bits)

    if pkcs == 1:
        private_key = key.export_key(format=pk_format)
    else:
        private_key = key.export_key(
            format=pk_format,
            passphrase=passphrase,
            pkcs=pkcs,
            protection=f"PKBDF2WithHMAC-{hash}And{cipher}",
        )

    public_key = key.public_key().export_key(format=pb_format)

    return private_key, public_key


def main():
    key = RSA.generate(2048)
    private_key = key.export_key(format="PEM", pkcs=1)
    pub_key = key.public_key().export_key(format="OpenSSH")
    with open("my_pubkey.pem", "wb") as f:
        f.write(pub_key)


if __name__ == "__main__":
    main()
