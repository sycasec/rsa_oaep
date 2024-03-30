#!/usr/bin/env python3

from typing import Optional

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS, pss, pkcs1_15
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
    phrase: str,
    curve: str = "p256",
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


def RSA_PSS_sign_message(private_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    h = SHA256.new(ciphertext)
    return pss.new(private_key).sign(h)


def RSA_PSS_verify_message(
    public_key: RSA.RsaKey, ciphertext: bytes, signature: bytes
) -> bool:
    h = SHA256.new(ciphertext)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError) as e:
        print(f"{e}")
        return False


def RSA_SSA_sign_message(
    private_key: RSA.RsaKey,
    ciphertext: bytes,
) -> bytes:
    h = SHA256.new(ciphertext)
    return pkcs1_15.new(private_key).sign(h)


def RSA_SSA_verify_message(
    public_key: RSA.RsaKey, ciphertext: bytes, signature: bytes
) -> bool:
    h = SHA256.new(ciphertext)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError) as e:
        print(f"{e}")
        return False


def ECDSA_sign_message(
    private_key: ECC.EccKey,
    ciphertext: bytes,
    mode: str = "fips-186-3",
    encoding: str = "der",
) -> bytes:
    h = SHA256.new(ciphertext)
    signer = DSS.new(key=private_key, mode=mode, encoding=encoding)
    return signer.sign(h)


def ECDSA_verify_message(
    public_key: ECC.EccKey,
    ciphertext: bytes,
    signature: bytes,
) -> bool:
    h = SHA256.new(ciphertext)
    verifier = DSS.new(public_key, "fips-186-3")
    try:
        verifier.verify(h, signature)
        return True
    except ValueError as e:
        print(f"{e}")
        return False


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
