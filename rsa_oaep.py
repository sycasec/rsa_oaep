#!/usr/bin/env python3

from parser_setup import gen_parser
from typing import Optional

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import HMAC, SHA256


# --------------------------- functions ----------------------------
def generate_rsa_key_pair(
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
                protection=f"PBKDF2WithHMAC-{hash}And{cipher}",
            )
        else:
            private_key = key.export_key(
                format=pk_format,
                passphrase=phrase,
                pkcs=pkcs,
            )
    public_key = key.public_key().export_key(format=pb_format)

    return private_key, public_key


def generate_ecc_key_pair(
    pk_format,
    pb_format,
    curve: str,
    phrase: str,
    cipher: str = "AES256-CBC",
    hash: str = "SHA512",
) -> tuple[bytes, bytes]:
    key = ECC.generate(curve=curve)
    private_key: bytes = key.export_key(
        format=pk_format,
        passphrase=phrase,
        protection=f"PBKDF2WithHMAC-{hash}And{cipher}",
    )

    public_key: bytes = key.public_key().export_key(format=pb_format)

    return private_key, public_key


def encrypt_message(public_key: RSA.RsaKey, message: str) -> bytes:
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode("utf-8"))


def decrypt_message(private_key: RSA.RsaKey, ciphertext: bytes) -> str:
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext).decode("utf-8")


def HMAC_sign_message(secret: str, message: bytes) -> str:
    h = HMAC.new(secret.encode("utf-8"), digestmod=SHA256)
    h.update(message)
    return h.hexdigest()


def HMAC_verify_message(secret: str, message: bytes, signature: str) -> bool:
    h = HMAC.new(secret.encode("utf-8"), digestmod=SHA256)
    h.update(message)
    try:
        h.hexverify(signature)
        return True
    except ValueError:
        return False


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
    except ValueError as e:
        print(f"{e}")


def decrypt_helper(args):
    try:
        priv_key = RSA.importKey(open(args.priv_key).read())
        if args.msg:
            message = decrypt_message(priv_key, args.msg)
        elif args.filepath:
            with open(args.filepath, "rb") as ciphertext_file:
                ciphertext = ciphertext_file.read()

            message = decrypt_message(priv_key, ciphertext)
        else:
            print("no ciphertext supplied")
            exit(1)

        print(message)
    except ValueError as e:
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
