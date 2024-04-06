# rsa_oaep
Now you might think this is an API. It kind of is. It's all in the name. `rsa_oaep` is a cli-based RSA-OAEP encryption and decryption tool with signing and verification. It also supports four different signing methods. Signing, verification, encryption, and decryption are all separate `commands`, but since they are all isolated and have output files, they are expected to be used in a encrypt-then-sign and verify-then-decrypt manner. 

## installation
Clone the repository first. Make sure you have `python3` and `PyCryptodome` installed. If you don't:
```bash
pip3 install pycryptodome
```

If you aren't using `pip`, you most likely can install it from your package manager
```bash
    # arch
sudo pacman -Sy python-pycryptodome
```

## Features
- [x] RSA key generation
- [x] ECC key generation
- [x] RSA-OAEP with SHA256 encryption and decryption
- [x] HMAC signing and verification
- [x] RSA SSA pkcs1v15 signing and verification
- [x] RSA PSS signing and verification
- [x] ECC signing and verification
- [ ] hack into the mainframe 😔

## usage
It is a relatively simple command line tool. You can run `rsa_oaep` with `python3` or `python` with the `--help` flag to see the available options.

```bash
    python rsa_oaep --help
```

Or you can `chmod +x` the file and run it directly
```bash
chmod +x rsa_oaep
./rsa_oaep --help
```

> [!WARNING] 
>
> Use at your own risk! When downloading scripts from the internet, always check what it does first. If this somehow breaks your computer, I am not responsible.

### Help

```bash
rsa_oaep -h
usage: rsa_oaep [-h] {ets,encrypt,decrypt,sign,verify,rsa_keygen,ecc_keygen} ...

  /$$$$$$   /$$$$$$$  /$$$$$$           /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$
 /$$__  $$ /$$_____/ |____  $$ /$$$$$$ /$$__  $$ |____  $$ /$$__  $$ /$$__  $$
| $$  \__/|  $$$$$$   /$$$$$$$|______/| $$  \ $$  /$$$$$$$| $$$$$$$$| $$  \ $$
| $$       \____  $$ /$$__  $$        | $$  | $$ /$$__  $$| $$_____/| $$  | $$
| $$       /$$$$$$$/|  $$$$$$$        |  $$$$$$/|  $$$$$$$|  $$$$$$$| $$$$$$$/
|__/      |_______/  \_______/         \______/  \_______/ \_______/| $$____/
                                                                    | $$
                                                                    |__/

RSA-OAEP encryption and decryption + RSS (PSS, SSA), ECDSA, and HMAC signing and verification tool


positional arguments:
  {ets,encrypt,decrypt,sign,verify,rsa_keygen,ecc_keygen}
                        available commands
    ets                 Assumes that you already have generated encryption and signing keypairs: encrypt, then
                        sign a message
    encrypt             encrypt a message with RSA-OAEP
    decrypt             decrypt an RSA-OAEP encrypted message
    sign                sign a message with a digital signature
    verify              verify a message with a digital signature
    rsa_keygen          generate rsa keys
    ecc_keygen          generate ecc keys
```

To see additional help for a specific command, you can run `rsa_oaep <command> -h` or `rsa_oaep <command> --help`.

### Generating keys
To generate a hardended RSA private key and public key, you can run the following command:

```bash
rsa_oaep rsa_keygen --pkcs 8 --pk_format DER --pb_format PEM -p "secret"
```

Upon running, the script will prompt you if you want to change the destination file + name of the output keys. This generates a private key `.der` private key and a `.pem` public key. The private key has the passphrase "secret" which you will need to decrypt a message signed with the corresponding public key. You can use the same method to generate a signing keypair.

### Generating ECC keys for signing
To generate a ECC private key and public key for signing and verification, you can run the following command:
```bash
rsa_oaep ecc_keygen --curve p256 --phrase "ecc_secret" --pk_format DER --pb_format PEM
```

Similar to the RSA key generation, this will generate a private key and public key in the specified formats. The private key is encrypted with the passphrase "ecc_secret".
