#!/usr/bin/env python3

import argparse


def gen_parser():
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
        "--pk_format",
        choices=["PEM", "DER"],
        default="DER",
        help="Output format for the keys",
    )

    keygen_parser.add_argument(
        "--pb_format",
        choices=["PEM", "DER", "OpenSSH"],
        default="PEM",
        help="Output format for the public key",
    )

    keygen_parser.add_argument(
        "--phrase", help="Passphrase for PKCS#8 key (required if PKCS#8)"
    )
    keygen_parser.add_argument(
        "--bits",
        choices=[1024, 2048, 3072],
        default=2048,
        help="key size in bits",
        type=int,
    )
    keygen_parser.add_argument(
        "--cipher",
        choices=[
            "AES128-GCM",
            "AES192-GCM",
            "AES256-GCM",
            "AES128-CBC",
            "AES192-CBC",
            "AES-256-CBC",
            "DES-EDE3-CBC",
        ],
        default="AES256-CBC",
        help="cipher for pkcs#8 private key derivation",
    )

    keygen_parser.add_argument(
        "--hash",
        choices=[
            "SHA1",
            "SHA224",
            "SHA256",
            "SHA384",
            "SHA512-224",
            "SHA512-256",
            "SHA3-224",
            "SHA3-256",
            "SHA3-384",
            "SHA3-512",
        ],
        default="SHA512",
        help="hash for pkcs#8 private key derivation",
    )

    return parser
