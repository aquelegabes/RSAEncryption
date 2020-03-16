# RSA Encryption Console

<p align="center">
<a href="https://github.com/gabesantos1/RSAEncryption/blob/master/LICENSE"><img alt="undefined" src="https://img.shields.io/github/license/gabesantos1/RSAEncryption"></a>
<br>
</p>

## Usage: rsaencryption [OPTIONS]
##### Encrypts, decrypts, sign and verifies signature on files. Encrypt files using Rijndael encryption algorithm with RSA keys.
##### Note: When encrypting or decrypting ```--target``` can be used to specify a directory.
##### Note: If no output is specified, the default output path is Environment.CurrentDirectory.
##### Note: Recommendation is that files are no larger than 10mb, cause it'll take longer.
##### Note: When using decrypt on a directory it searches for files that contains ```.encrypted``` on it's name.

### Options:
```
  -d, --decrypt               decrypts the encrypted data, requires private key 
                                  [ACTION]
```
```
  -e, --encrypt               encrypts the data, requires public key 
                                  [ACTION]
```
```
  -h, --help                  show this message and exit 
                                  [ACTION]
```
```
  -m, --merge                 merge signature with another file, use --signaturefile,
                                  requires private key
                                  [ACTION]
```
```
  -o, --output=VALUE          path to output encrypted files
```
```
  -s, --sign                  signs the encrypted data, requires private key 
                                  [ACTION]
```
```
  -t, --target=VALUE          file or directory to be encrypted, decrypted or to
                                  verify its signature, if target is a directory 
                                  encrypts/decrypts all file from that directory
```
```
  -u, --unmerge               unmerge signature from file, requires private key
                                  [ACTION]
```
```
  -v, --verifysignature       verify if signed data is trustworthy, requires public key
                                  [ACTION], use --target for signed data and 
                                  --signaturefile for signature file
```
```
  -x, --examples              show specific examples 
                                  [ACTION]
```
```
  --hashalg=VALUE             type of hashing algorithm, examples: SHA1, SHA256.
                                  default value is SHA256
```
```
  --keyfilename=VALUE           when generating a new key use this to choose file
                                  name, default is "key"
```
```
  --newkey=VALUE              generates a new RSA Key with specified key size,
                                  exports public and private separetly 
                                  [ACTION]
```
```
  --publickey=VALUE           key used to encrypt and verify signature (.pem file)
```
```
  --privatekey=VALUE          key used to sign and decrypt (.pem file)
```
```
  --signaturefile=VALUE       signature file generated based on encrypted file
```
```
  --verbose                   increase verbosity
```
```
  --version                   shows version 
                                  [ACTION]
```
### Examples:
* Encrypting and signing:
```
  rsaencryption -e -s --target=.\\myfile.pdf --publickey=.\\pub.key.pem --privatekey=\\priv.key.pem
        Encrypts using public key and sign the specified file using default output with specified private key
```
* Decrypting:
```
  rsaencryption -d --target=.\\myfile.encrypted.pdf --output=.\\ --privatekey=.\\priv.key.pem --verbose
        Decrypts specified file on specified output using selected key with increase verbosity
```
* Generating new key:
 ```
  rsaencryption --newkey=4096 -o=.\
        Generates a new key with chosen size at selected path
```
* Signing only:
```
  rsaencryption  --sign --target=.\\myfile.docx --privatekey=.\\priv.key.pem
        Signs the specified file using default output with specified private key
```
* Verifying signature: 
```
  rsaencryption -vs --target=.\\myfile.txt --signaturefile=.\\myfile.signature.txt --publickey=.\\pub.key.pem
        Checks if signature file is valid
```
