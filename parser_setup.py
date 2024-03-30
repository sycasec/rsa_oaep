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

    subparsers = parser.add_subparsers(dest="command", help="available commands")

    # -------------------------------- encrypt --------------------------------

    # TODO: add an argument for file input
    encrypt_parser = subparsers.add_parser(
        "encrypt", help="encrypt a message with RSA-OAEP"
    )
    encrypt_parser.add_argument(
        "--pub_key", required=True, help="receiver public key file"
    )
    encrypt_parser.add_argument("--msg", required=True, help="message to encrypt")

    # -------------------------------- decrypt --------------------------------

    decrypt_parser = subparsers.add_parser(
        "decrypt", help="decrypt an RSA-OAEP encrypted message"
    )

    decrypt_parser.add_argument(
        "--priv_key", required=True, help="receiver private key"
    )
    decrypt_parser.add_argument("--msg", help="raw ciphertext bytes to decrypt")
    decrypt_parser.add_argument("--filepath", help="filepath storing ciphertext")

    # -------------------------------- sign --------------------------------
    sign_parser = subparsers.add_parser(
        "sign", help="sign a message with a digital signature"
    )

    sign_parser.add_argument(
        "--scheme",
        choices=["ECDSA", "RSA_PSS", "RSA_SSA", "HMAC"],
        required=True,
        help="digital signature scheme to be used in signing",
    )

    sign_parser.add_argument(
        "--cipher_path",
        metavar="/path/to/ciphertext",
        help="path to the file containing the message to be signed",
    )

    sign_parser.add_argument(
        "--ciphertext",
        help="message in bytes to be signed",
    )

    sign_parser.add_argument(
        "--priv_key",
        help="private key file path for signing (cannot be used for HMAC)",
    )

    sign_parser.add_argument(
        "--secret",
        help="secret key for HMAC signing (only used for HMAC)",
    )

    # -------------------------------- verify --------------------------------

    verify_parser = subparsers.add_parser(
        "verify", help="verify a message with a digital signature"
    )

    verify_parser.add_argument(
        "--scheme",
        choices=["ECDSA", "RSA_PSS", "RSA_SSA", "HMAC"],
        required=True,
        help="digital signature scheme to be used in verification",
    )

    verify_parser.add_argument("--signature", help="signature to be verified")

    verify_parser.add_argument(
        "--signature_path",
        help="path to the file containing the signature to be verified",
    )

    verify_parser.add_argument(
        "--cipher_path",
        metavar="/path/to/ciphertext",
        help="path to the file containing the signed ciphertext",
    )

    verify_parser.add_argument(
        "--ciphertext",
        help="signed ciphertext in bytes",
    )

    verify_parser.add_argument(
        "--pub_key",
        help="public key file path for verifying the signature (cannot be used for HMAC)",
    )

    verify_parser.add_argument(
        "--secret",
        help="secret key string for HMAC verification (only used for HMAC)",
    )

    # --------------------------------- rsa keygen ---------------------------------

    rsa_keygen_parser = subparsers.add_parser(
        "rsa_keygen", help="generate rsa-oaep keys"
    )
    rsa_keygen_parser.add_argument(
        "--pkcs", type=int, choices=[1, 8], required=True, help="PKCS standard (1 or 8)"
    )
    rsa_keygen_parser.add_argument(
        "--pk_format",
        choices=["PEM", "DER"],
        default="DER",
        help="output format for private key",
    )

    rsa_keygen_parser.add_argument(
        "--pb_format",
        choices=["PEM", "DER", "OpenSSH"],
        default="PEM",
        help="output format for public key",
    )

    rsa_keygen_parser.add_argument(
        "--phrase", help="passphrase for PKCS#8 key (required if PKCS#8)"
    )
    rsa_keygen_parser.add_argument(
        "--bits",
        choices=[1024, 2048, 3072],
        default=2048,
        help="key size in bits",
        type=int,
    )
    rsa_keygen_parser.add_argument(
        "--cipher",
        choices=[
            "AES128-GCM",
            "AES192-GCM",
            "AES256-GCM",
            "AES128-CBC",
            "AES192-CBC",
            "AES256-CBC",
            "DES-EDE3-CBC",
        ],
        default="AES256-CBC",
        help="cipher for pkcs#8 private key derivation",
    )

    rsa_keygen_parser.add_argument(
        "--hash",
        choices=[
            "SHA256",
            "SHA384",
            "SHA512-224",
            "SHA512-256",
            "SHA3-256",
            "SHA3-384",
            "SHA3-512",
        ],
        default="SHA512",
        help="hash for pkcs#8 private key derivation",
    )

    # --------------------------------- ecc keygen ---------------------------------

    ecc_keygen_parser = subparsers.add_parser("ecc_keygen", help="generate ecc keys")
    ecc_keygen_parser.add_argument(
        "--curve",
        choices=["p256", "p384", "p521"],
        required=True,
        help="NIST standard elliptic curve starting at the recommended prime field of 256 bits",
    )

    ecc_keygen_parser.add_argument(
        "--phrase", required=True, help="passphrase to protect private key"
    )

    ecc_keygen_parser.add_argument(
        "--pk_format",
        choices=["PEM", "DER", "SEC1", "raw"],
        default="DER",
        help="output format for private key",
    )

    ecc_keygen_parser.add_argument(
        "--pb_format",
        choices=["PEM", "DER", "OpenSSH" "SEC1", "raw"],
        default="PEM",
        help="output format for public key",
    )

    ecc_keygen_parser.add_argument(
        "--cipher",
        choices=[
            "AES128-GCM",
            "AES192-GCM",
            "AES256-GCM",
            "AES128-CBC",
            "AES192-CBC",
            "AES256-CBC",
            "DES-EDE3-CBC",
        ],
        default="AES256-CBC",
        help="cipher for pkcs#8 private key derivation",
    )

    ecc_keygen_parser.add_argument(
        "--hash",
        choices=[
            "SHA256",
            "SHA384",
            "SHA512-224",
            "SHA512-256",
            "SHA3-256",
            "SHA3-384",
            "SHA3-512",
        ],
        default="SHA512",
        help="hash for pkcs#8 private key derivation",
    )

    return parser
