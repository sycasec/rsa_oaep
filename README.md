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


## Features Quicklist 
- [x] RSA key generation
- [x] ECC key generation
- [x] RSA-OAEP with SHA256 encryption and decryption
- [x] HMAC signing and verification
- [x] RSA SSA pkcs1v15 signing and verification
- [x] RSA PSS signing and verification
- [x] ECC signing and verification
- [ ] hack into the mainframe 😔
