#!/usr/bin/env python3

from parser_setup import gen_parser
from typing import Optional

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15

# from Crypto.Hash import SHA256, SHA512


# --------------------------- functions ----------------------------
def generate_key_pair(
    pk_format: str,
    pb_format: str,
    bits: int = 2048,
    phrase: Optional[str] = None,
    pkcs: int = 1,
    cipher: str = "AES256-CBC",
    hash: str = "SHA512",
):
    key = RSA.generate(bits)

    if pkcs == 1:
        private_key = key.export_key(format=pk_format)
    else:
        if pk_format == "DER":
            private_key = key.export_key(
                format=pk_format,
                passphrase=phrase,
                pkcs=pkcs,
                protection=f"PKBDF2WithHMAC-{hash}And{cipher}",
            )
        else:
            private_key = key.export_key(
                format=pk_format,
                passphrase=phrase,
                pkcs=pkcs,
            )
    public_key = key.public_key().export_key(format=pb_format)
    print(type(public_key))

    return private_key, public_key


def encrypt_message(public_key: RSA.RsaKey, message: str) -> bytes:
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode("utf-8"))
    return ciphertext


# ----------------------------- helpers ------------------------------
def keygen_helper(args):
    if args.pkcs == 8:
        if args.phrase is None:
            print("Passphrase required for PKCS#8")
            exit(1)
        if args.pk_format == "PEM" and (
            args.cipher is not None or args.hash is not None
        ):
            print("Cipher and hash are not supported for PEM format")
            exit(1)
    keygen_args = {key: value for key, value in vars(args).items() if key != "command"}
    private_key, public_key = generate_key_pair(**keygen_args)
    pk_fname = "./private_key"
    pb_fname = "./public_key"
    npk_fname = input("please enter private key filename (default is ./private_key):")
    npb_fname = input("please enter public key filename (default is ./public_key):")

    if npk_fname.strip():
        pk_fname = npk_fname
    if npb_fname.strip():
        pb_fname = npb_fname

    print("saving keys...")
    with open(f"{pk_fname}.{args.pk_format.lower()}", "wb") as pkf, open(
        f"{pb_fname}.{args.pb_format.lower()}", "wb"
    ) as pbf:
        pkf.write(private_key)
        pbf.write(public_key)


def main():
    parser = gen_parser()

    args = parser.parse_args()
    if args.command == "keygen":
        keygen_helper(args)
        pass
    pass


if __name__ == "__main__":
    main()
