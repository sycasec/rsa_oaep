#!/usr/bin/env python3

import argparse

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
    # key = RSA.generate(2048)
    # private_key = key.export_key(format="PEM", pkcs=1)
    # pub_key = key.public_key().export_key(format="OpenSSH")
    # with open("my_pubkey.pem", "wb") as f:
    #     f.write(pub_key)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
  /$$$$$$   /$$$$$$$  /$$$$$$           /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$ 
 /$$__  $$ /$$_____/ |____  $$ /$$$$$$ /$$__  $$ |____  $$ /$$__  $$ /$$__  $$
| $$  \__/|  $$$$$$   /$$$$$$$|______/| $$  \ $$  /$$$$$$$| $$$$$$$$| $$  \ $$
| $$       \____  $$ /$$__  $$        | $$  | $$ /$$__  $$| $$_____/| $$  | $$
| $$       /$$$$$$$/|  $$$$$$$        |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$$$$$$/
|__/      |_______/  \_______/         \______/  \_______/ \_______/| $$____/ 
                                                                    | $$      
                                                                    |__/      

RSA-OAEP encryption and decryption + signing and verification tool
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Subparser for the encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt some data")

    # Subparaser for key generation
    keygen_parser = subparsers.add_parser("keygen", help="Generate RSA-OAEP keys")
    keygen_parser.add_argument(
        "--pkcs", type=int, choices=[1, 8], required=True, help="PKCS standard (1 or 8)"
    )
    keygen_parser.add_argument(
        "--format",
        choices=["PEM", "DER"],
        required=True,
        help="Output format for the keys",
    )
    keygen_parser.add_argument(
        "--phrase", help="Passphrase for PKCS#8 key (required if PKCS#8)"
    )

    args = parser.parse_args()
    if args.command == "keygen":
        # key_gen_helper(args)
        pass
    pass


if __name__ == "__main__":
    main()
