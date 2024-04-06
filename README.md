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

```python
$ ./rsa_oaep -h
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

### Generating keys
To generate an RSA encryption keypair, run the following command:

```python

```
