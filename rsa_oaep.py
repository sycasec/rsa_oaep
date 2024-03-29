#!/usr/bin/env python3

from parser_setup import gen_parser
from crypto_functions import *
from typing import Optional

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS, pss, pkcs1_15
from Crypto.Hash import HMAC, SHA256


# ----------------------------- helpers ------------------------------
def keygen_helper(args):
    # input verification
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
    private_key, public_key = generate_rsa_key_pair(**keygen_args)

    # customize output filename / location
    pk_fname = "./private_key"
    pb_fname = "./public_key"
    npk_fname = input("please enter private key filename (default is ./private_key):")
    npb_fname = input("please enter public key filename (default is ./public_key):")

    if npk_fname.strip():
        pk_fname = npk_fname
    if npb_fname.strip():
        pb_fname = npb_fname

    # output keys as files
    print("saving keys...")
    with open(f"{pk_fname}.{args.pk_format.lower()}", "wb") as pkf, open(
        f"{pb_fname}.{args.pb_format.lower()}", "wb"
    ) as pbf:
        pkf.write(private_key)
        pbf.write(public_key)


def sign_helper(args):
    if args.cipher_path and args.ciphertext:
        print("cannot supply both ciphertext and a filepath")
        exit(1)

    if args.scheme != "HMAC":
        if not args.priv_key:
            print("no private key supplied! exiting.")
            exit(1)
        try:
            if args.scheme.startswith("RSA"):
                priv_key = RSA.import_key(open(args.priv_key).read())
                if args.cipher_path:
                    with open(args.cipher_path, "rb") as cipher_file:
                        ciphertext = cipher_file.read()
                elif args.ciphertext:
                    ciphertext = args.ciphertext.encode().decode("unicode_escape")
                else:
                    raise Exception("no ciphertext supplied")

                if args.scheme == "RSA_PSS":
                    signature = RSA_PSS_sign_message(priv_key, ciphertext)
                elif args.scheme == "RSA_SSA":
                    signature = RSA_SSA_sign_message(priv_key, ciphertext)
                else:
                    raise Exception("invalid scheme")

                default_sig_fname = "./sig.bin"
                sig_fname = input("enter signature filename (default: ./sig.bin): ")
                if sig_fname.strip():
                    default_sig_fname = sig_fname

                with open(default_sig_fname, "wb") as sig_file:
                    sig_file.write(signature)

            elif args.scheme == "ECDSA":
                key = ECC.import_key(open(args.priv_key).read())
                if args.cipher_path:
                    with open(args.cipher_path, "rb") as cipher_file:
                        ciphertext = cipher_file.read()
                elif args.ciphertext:
                    ciphertext = args.ciphertext.encode().decode("unicode_escape")
                else:
                    raise Exception("no ciphertext supplied")

                signature = ECDSA_sign_message(key, ciphertext)

                default_sig_fname = "./sig.bin"
                sig_fname = input("enter signature filename (default: ./sig.bin): ")
                if sig_fname.strip():
                    default_sig_fname = sig_fname

                with open(default_sig_fname, "wb") as sig_file:
                    sig_file.write(signature)

        except Exception as e:
            print(f"{e}")
            exit(1)
    elif args.scheme == "HMAC":
        if not args.secret:
            print("no secret key supplied! exiting.")
            exit(1)
        try:
            if args.cipher_path:
                with open(args.cipher_path, "rb") as cipher_file:
                    ciphertext = cipher_file.read()
            elif args.ciphertext:
                ciphertext = args.ciphertext.encode().decode("unicode_escape")
            else:
                raise Exception("no ciphertext supplied")

            signature = HMAC_sign_message(args.secret, ciphertext)

            default_sig_fname = "./sig.hex"
            sig_fname = input("enter signature filename (default: ./sig.hex): ")
            if sig_fname.strip():
                default_sig_fname = sig_fname

            with open(default_sig_fname, "w") as sig_file:
                sig_file.write(signature)

        except Exception as e:
            print(f"{e}")
            exit(1)
    else:
        print("invalid scheme")
        exit(1)


def encrypt_helper(args):
    try:
        pub_key = RSA.import_key(open(args.pub_key).read())
        ciphertext = encrypt_message(pub_key, args.msg)
        save = input("write ciphertext to file? [Y/n]: ")
        if save.strip().lower() not in ["n", "no"] or save == "":
            fname = "cipher_text.bin"
            n_fname = input("enter file name (default: cipher_text.bin): ")
            if n_fname.strip():
                fname = n_fname

            with open(f"{fname}", "wb") as outfile:
                outfile.write(ciphertext)
        else:
            print(ciphertext)
    except Exception as e:
        print(f"{e}")


def decrypt_helper(args):
    if args.msg and args.filepath:
        print("cannot supply both a message and a file")
        exit(1)
    try:
        priv_key = RSA.importKey(open(args.priv_key).read())
        if args.msg:
            message = decrypt_message(
                priv_key, args.msg.encode().decode("unicode_escape")
            )
        elif args.filepath:
            with open(args.filepath, "rb") as ciphertext_file:
                ciphertext = ciphertext_file.read()

            message = decrypt_message(priv_key, ciphertext)
        else:
            print("no ciphertext supplied")
            exit(1)

        print(message)
    except Exception as e:
        print(f"{e}")


# ----------------------------- main ------------------------------
def main():
    parser = gen_parser()

    args = parser.parse_args()
    if args.command == "keygen":
        keygen_helper(args)
    elif args.command == "encrypt":
        encrypt_helper(args)
    elif args.command == "decrypt":
        decrypt_helper(args)
        pass


if __name__ == "__main__":
    main()
