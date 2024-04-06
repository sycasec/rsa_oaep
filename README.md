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

## Usage
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
$ rsa_oaep rsa_keygen --pkcs 8 --pk_format DER --pb_format PEM -p "secret"
generating keys...
please enter private key filename (default is ./keys/rsa_private_key): keys/rsa_priv
please enter public key filename (default is ./keys/rsa_public_key): keys/rsa_pub
saving keys...
keys saved!
```

Upon running, the script will prompt you if you want to change the destination file + name of the output keys. This generates a private key `.der` private key and a `.pem` public key. The private key has the passphrase "secret" which you will need to decrypt a message signed with the corresponding public key. You can use the same method to generate a signing keypair.

### Generating ECC keys for signing
To generate a ECC private key and public key for signing and verification, you can run the following command:
```bash
rsa_oaep ecc_keygen --curve p256 --phrase "ecc_secret" --pk_format DER --pb_format PEM
please enter private key filename (default is ./keys/ecc_private_key): keys/sign_pk
please enter public key filename (default is ./keys/ecc_public_key): keys/sign.pub
saving keys...
keys saved!
```

Similar to the RSA key generation, this will generate a private key and public key in the specified formats. The private key is hardened with the passphrase "ecc_secret".

### Encrypting a message
To encrypt a message, you need a reciever public key. For demonstration, we will be sending a message to ourselves using the generated keypair.

But first, let's use a 140 character message.
```bash
echo -n "Hello, this is a 140 character message. There is definitely no context to be taken from this message other than that it has 140 characters." > message.txt
```

We can confirm this with the following commands:
```bash
$ wc -c message.txt
140 message.txt
$ xxd message.txt
00000000: 4865 6c6c 6f2c 2074 6869 7320 6973 2061  Hello, this is a
00000010: 2031 3430 2063 6861 7261 6374 6572 206d   140 character m
00000020: 6573 7361 6765 2e20 5468 6572 6520 6973  essage. There is
00000030: 206e 6f20 636f 6e74 6578 7420 636f 6e74   no context cont
00000040: 6169 6e65 6420 746f 2074 6869 7320 6d65  ained to this me
00000050: 7373 6167 6520 6f74 6865 7220 7468 616e  ssage other than
00000060: 2074 6861 7420 6974 2063 6f6e 7461 696e   that it contain
00000070: 7320 6120 746f 7461 6c20 6f66 2031 3430  s a total of 140
00000080: 2063 6861 7261 6374 6572 732e             characters.
```

Now we can encrypt the message with the public key:
```bash
$ ./rsa_oaep encrypt --pub_key keys/rsa_pub.pem -f message.txt
reading public key...
write ciphertext to file? [Y/n]:
enter file name (default: cipher_text.raw):
saving ciphertext...
ciphertext saved!
```

### Signing a message
Following through using our ECC keys, sign a message with the private key by running the following command:

```bash
$ ./rsa_oaep sign --scheme ECDSA --priv_key keys/sign_pk.der --cipher_path cipher_text.raw --phrase "ecc_secret"
reading private key...
reading ciphertext...
signing message...
enter signature filename (default: ./sig.raw):
saving signature...
signature saved!
```

If a secret phrase was supplied during key generation, you will need to enter it to sign the message. The signature is saved in the file `sig.raw`.

### Verifying a signature
To verify the signature, you can run the following command:

```bash
$ ./rsa_oaep verify --scheme ECDSA --signature_path sig.raw --cipher_path cipher_text.raw  --pub_key keys/sign.pub.pem
signature is authentic: True
```

### Decrypting a message
To decrypt the message, you can run the following command:

```bash
$ ./rsa_oaep decrypt --priv_key keys/rsa_priv.der --cipher_path cipher_text.raw --phrase "secret"
decrypted message: Hello, this is a 140 character message. There is no context contained to this message other than that it contains a total of 140 characters.
```

Similar to signing, if a secret phrase was supplied during key generation, you will need to enter it to decrypt the message. The decrypted message is printed to the console.


## Methodology
There is no stopping you from just skipping signing and verification. This was modeled after the fact that in the `encrypt-then-sign` scheme, both the `ciphertext` and `tag` are sent to the reciever.

### RSA Key generation
`rsa_oaep` provides several options regarding RSA key generation, such as:
- specifying the public and private key format
- specifiying the pkcs standard to use for key generation
- specifying a passphrase
- specifying the RSA modulus bits [1024, *{1648}*, 2048, 3072]
- specifiying the cipher and hash to be used for hardened `pkcs8` key derivation

While hardening is not necessary, it is simply there to provide security. Regarding bit choices, the default is 1648 due to the [RFC 8017 standard](https://www.rfc-editor.org/rfc/rfc8017#section-7.1.1) which shows that:
- `mLen <= k - 2hLen - 2`
- where `mLen` is the length of the message
- `k` is the length in octets of the RSA modulus `n`
- `hLen` is the length in octets of the hash function output

**To get an `mLen` of 140, we use the formula to get a total of 1648 bits for `k`.**

### ECC Key generation
`rsa_oaep` provides several options regarding ECC key generation, such as:
- specifying the curve to use [*{p256}*, p384, p521]
- specifying the public and private key format
- specifying a passphrase
- specifying the cipher and hash to be used for hardened key derivation

The NIST curves start at the standard 256 bits. For more information, you can check the [NIST curves](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).

### Encryption and Decryption
The generated RSA keys are used to encrypt and decrypt with the `RSA-OAEP (Optimal Assymetric Encryption Padding)` scheme, which is a probabilistic encryption scheme. The `OAEP` scheme is used to prevent chosen-ciphertext attacks. The `RSA-OAEP` scheme uses a mask generation function and a hash function to randomize the message before encryption. The `RSA-OAEP` scheme is defined in [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017#section-7.1.1). The `RSA-OAEP` scheme is hardcoded to use `SHA256` as the hash function.

### Signature and Verification
`rsa_oaep` provides several options regarding signing and verification, such as:
- specifying the signing scheme [RSA-PSS, RSA-SSA, ECDSA, HMAC]

It is worth noting that the `RSA-SSA` signature scheme is an older scheme that is deterministic, but it has not been broken. It is more formally called `RSA-PKCS1-v1_5` and is defined in [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017#section-8.2).
`RSA-PSS` is a probabilistic scheme with a securtity proof for the padding and is defined in [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017#section-8.1). 
`ECDSA` is a signature scheme that uses the `ECC` keys to sign and verify messages, providing the same amount of security as RSA keys yet being much shorter. It is defined in [FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf).
`HMAC` is a symmetric key signature scheme that uses a hash function to sign and verify messages. It is defined in [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104). `rsa_oaep` requires the `secret key` as an input if HMAC is used, and is there just for the sake of being added.


