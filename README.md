# RSA Encryption Console

<p align="center">
<a href="https://github.com/gabesantos1/RSAEncryption/blob/master/LICENSE"><img alt="undefined" src="https://img.shields.io/github/license/gabesantos1/RSAEncryption"></a>
<br>
</p>

## Usage: rsaencryption [OPTIONS]
##### Generates key pair and encrypted key pair.
##### Encrypts, decrypts, sign or verify signatures.
##### [Rijndael](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encryption algorithm using [RSA key pair](https://en.wikipedia.org/wiki/RSA_(cryptosystem)).
##### Check some [hashing algorithm names](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.hashalgorithmname?view=netcore-3.1#remarks).
##### Note: When encrypting or decrypting ```--target``` can be used to specify a directory instead of a single file.
##### Note: If no output is specified, the default output path is [Environment.CurrentDirectory](https://docs.microsoft.com/en-us/dotnet/api/system.environment.currentdirectory?view=netcore-3.1).
##### Note: Recommendation is that files are no larger than 10mb, cause it'll take longer.
##### Note: When using decrypt *on a directory it searches for files that contains ```.encrypted``` on its names.*
##### Note: Key size **MUST** be between 384 and 16384 bits in sizes incremented by 8, e.g.: 512, 520, 528 etc.

### Options:
```
  -d, --decrypt               decrypts encrypted data, requires private key 
                                  [ACTION]
```
```
  -e, --encrypt               encrypts data, requires public key 
                                  [ACTION]
```
```
  -h, --help                  show this message and exit 
                                  [ACTION]
```
```
  -n, -newkey                 generates a new RSA Key with default key size and name,
                                  exports public and private separetly 
                                  [ACTION]
```
```
  -m, --merge                 merge signature and original data, use --signaturefile,
                                  warns if no key was specified
                                  [ACTION]
```
```
  -o, --output=VALUE          path to output files
```
```
  -p, --password              when generating/using a new key use this flag to set password.
                                  when using this flag must always be a private key.
```
```
  -s, --sign                  signs data, requires private key 
                                  [ACTION]
```
```
  -t, --target=VALUE          file or directory to be encrypted, decrypted or to
                                  verify its signature, if target is a directory 
                                  encrypts/decrypts all file from that directory
```
```
  -u, --unmerge               unmerge signature from data, requires public key used
                                  used in signature, use --hashalg to identify wich
                                  hashing algorithm was used and verify signature
                                  (if none was specified uses default: SHA256)
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
  --keysize=VALUE             when generating key use this to choose its size,
                                  minimum size is 384 and maximum is 16384, 
                                  key size must be in increments of 8 bits.
```
```
  --keyfilename=VALUE         when generating a new key use this to choose file
                                  name, default is "key"
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
* Encrypting:
```
  [rsaencryption -e -t=.\\myfile.pdf -k=.\\pub.key.pem]
        Encrypts target data using default output.
```
* Decrypting:
```
  [rsaencryption -d -t=.\\myfile.encrypted.pdf -o=.\\ -k=.\\priv.key.pem --verbose]
        Decrypts specified file on specified output using selected key
            with increase verbosity.
```
* Generating new key with chosen size and name:
```
  [rsaencryption -n --keysize=1024 --keyfilename=my_1024_key -o=.]
        Generates a new key with specified name and size at selected path.
```
* Generating new encrypted key
```
  [rsaencryption -n -p]
        Generates a new encrypted key using default values.
```
* Signing:
```
  [rsaencryption -s --hashalg=SHA512 -t=.\\myfile.docx -k=.\\priv.key.pem]
        Signs the selected file using default output with specified private
            key and chosen hashing algorithm. (if hash algorithm not chosen
            default will be SHA256)
```
* Verifying signature: 
```
  [rsaencryption -v --hashalg=SHA512 -t=.\\myfile.txt --signaturefile=.\\myfile.signature.txt -k=.\\pub.key.pem]
        Checks if signature file is valid. (if hash algorithm not chosen
            default will be SHA256)
```