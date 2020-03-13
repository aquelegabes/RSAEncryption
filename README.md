# RSA Encryption Console

## Usage: rsaencryption [OPTIONS]
##### Encrypts, decrypts, sign and verifies signature on files.
##### Note: When encrypting or decrypting --target can be used to specify a directory
##### Note: If no output is specified, the default output path is Environment.CurrentDirectory
##### Note: Recommendation is that files are no larger than 10mb, cause it'll take longer

### Options:
```
  -e, --encrypt               encrypts the data, requires public key
```
```
  -d, --decrypt               decrypts the encrypted data, requires private key
```
```
  -h, --help                  show this message and exit
```
```
  -o, --output=VALUE          path to output encrypted files
```
```
  -s, --sign                  signs the encrypted data, requires private key
```
```
  -t, --target=VALUE          file or directory to be encrypted, decrypted or to
                                  verify its signature, if target is a directory 
                                  encrypts/decrypts all file from that directory
```
```
  -v, --verifysignature       verify if signed data is trustworthy, requires public key
```
```
  -x, --examples              show specific examples
```
```
  --hashalg=VALUE             type of hashing algorithm, examples: SHA1, SHA256.
                                  default value is SHA256
```
```
  --newkey=VALUE              generates a new RSA Key with specified key size,
                                  default size is 2048bits, exports public and
                                  private separetly
```
```
  --publickey=VALUE           path where public key is stored (.pem file)
```
```
  --privatekey=VALUE          path where private key is stored (.pem file)
```
```
  --signaturefile=VALUE       signature file generated along side with its
                                  encryption
```
```
  --verbose                   increase debug message verbosity
```
```
  --version              shows version
```
### Examples:
* Encrypting and signing:
```
  rsaencryption -e -s --target=.\myfile.pdf --publickey=.\pubkey.pem
        Encrypts and sign the specified file using default output with specified public key
```
* Decrypting:
```
  rsaencryption -d --target=.\myfile.encrypted.pdf --output=.\ --privatekey=.\privkey.pem --verbose
        Decrypts specified file on specified output using selected key with increase verbosity
```
* Generating new key:
 ```
  rsaencryption --newkey=4096 -o=.\
        Generates a new key with chosen size at selected path
```
* Signing only:
```
  rsaencryption --sign --target=.\myfile.encrypted.docx --privatekey=.\privkey.pem
        Signs the specified file using default output with specified private key
```
* Verifying signature: 
```
  rsaencryption -vs --target=.\myfile.encrypted.txt --signaturefile=.\myfile.signature.txt --publickey=.\pubkey.pem
        Checks if signature file is valid
```
