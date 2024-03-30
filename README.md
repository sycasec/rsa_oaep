# machine problem II: rsa-oaep encryption and decryption with signing

## what?
- RSA-OAEP encrypt then sign -> verify then decrypt
- multiple signing methods

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

Please do NOT try to run `rsa_oaep` on another directory, as saving keys will not work. The script will look for the `keys` directory in the same directory as the `rsa_oaep` script.


## Functions roadmap
- [x] RSA key generation
- [x] RSA-OAEP encryption
- [x] RSA-OAEP decryption
- [x] HMAC signing
- [x] HMAC verification
- [x] RSA pkcs1v15 signing
- [x] RSA pkcs1v15 verification
- [x] RSA pss signing
- [x] RSA pss verification
- [ ] RSA-OAEP encrypt then sign -> verify then decrypt

## Argparse roadmap
- [x] RSA key generation
- [x] RSA-OAEP encryption
- [x] RSA-OAEP decryption
- [x] HMAC signing
- [x] HMAC verification 
- [x] RSA pkcs1v15 signing 
- [x] RSA pkcs1v15 verification
- [x] RSA pss signing
- [x] RSA pss verification
- [ ] RSA-OAEP encrypt then sign -> verify then decrypt
