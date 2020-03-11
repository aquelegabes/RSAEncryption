using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace RSAEncryption.Encryption
{
    /// <summary>
    /// Class responsible for generating, encrypting and signing messages. Using <see cref="System.Security.Cryptography.RSA" /> algorithm.
    /// </summary>
    public static class RSAMethods
    {
        /// <summary>
        /// Encrypts data with the <see cref="System.Security.Cryptography.RSA" /> algorithm.
        /// </summary>
        /// <param name="messages"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="MissingFieldException">Missing fields on key.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        public static ICollection<byte[]> Encrypt(ICollection<byte[]> data, EncryptionPairKey pubKey)
        {
            if (data?.Count == 0)
                throw new ArgumentNullException(
                    message: "At least one message is required.",
                    paramName: nameof(data)
                );

            if (pubKey?.Public == null)
            {
                throw new ArgumentNullException(
                    message: "Public key must not be null.",
                    paramName: nameof(pubKey)
                );
            }

            using (var rsa = new RSACryptoServiceProvider(pubKey.KeySize))
            {
                try
                {
                    var rsaParams = pubKey.ToRSAParameters(false);
                    var encryptedCollection = new List<byte[]>();
                    rsa.ImportParameters(rsaParams);

                    foreach (var msg in data)
                        encryptedCollection.Add(rsa.Encrypt(msg, false));

                    return encryptedCollection;
                }
                catch (ArgumentNullException ex)
                {
                    ex.Data["params"] = new List<object> { pubKey };
                    throw;
                }
                catch (MissingFieldException ex)
                {
                    ex.Data["params"] = new List<object> { pubKey };
                    throw;
                }
                catch (CryptographicException ex)
                {
                    ex.Data["params"] = new List<object> { pubKey };
                    throw;
                }
                catch (Exception ex)
                {
                    ex.Data["params"] = new List<object> { data, pubKey };
                    throw;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// Computes the hash value of the specified collection of byte array using the specified hash algorithm, and signs the resulting hash value.
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="MissingFieldException">Missing fields on key.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        public static ICollection<byte[]> SignData(ICollection<byte[]> encryptedData, EncryptionPairKey privateKey)
        {
            if (encryptedData?.Count == 0)
                throw new ArgumentNullException(
                    message: "At least one data must be available.",
                    paramName: nameof(encryptedData)
                );

            if (privateKey?.Private == null)
                throw new ArgumentNullException(
                    message: "Private key must not be null.",
                    paramName: nameof(privateKey)
                );

            using (var rsa = new RSACryptoServiceProvider(privateKey.KeySize))
            {
                using (var sha1 = new SHA1CryptoServiceProvider())
                {
                    try
                    {
                        var rsaParams = privateKey.ToRSAParameters(true);
                        var signedData = new List<byte[]>();

                        rsa.ImportParameters(rsaParams);

                        foreach (var data in encryptedData)
                            signedData.Add(rsa.SignData(data, sha1));

                        return signedData;
                    }
                    catch (ArgumentNullException ex)
                    {
                        ex.Data["params"] = new List<object> { privateKey };
                        throw;
                    }
                    catch (MissingFieldException ex)
                    {
                        ex.Data["params"] = new List<object> { privateKey };
                        throw;
                    }
                    catch (CryptographicException ex)
                    {
                        ex.Data["params"] = new List<object> { privateKey };
                        throw;
                    }
                    catch (Exception ex)
                    {
                        ex.Data["params"] = new List<object> { encryptedData, privateKey };
                        throw;
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }
            }
        }

        /// <summary>
        /// Verifies that a digital signature is valid by determining the hash value in the signature using the provided public key and comparing it to the hash value of the provided data.
        /// </summary>
        /// <param name="dataToVerify"></param>
        /// <param name="signedData"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="MissingFieldException">Missing fields on key.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        public static bool VerifySignedData(ICollection<byte[]> dataToVerify, ICollection<byte[]> signedData, EncryptionPairKey key)
        {
            if (dataToVerify?.Count == 0
                || signedData?.Count == 0)
                throw new ArgumentNullException(
                    message: "At least one data must be available.",
                    paramName: $"Params: [ {nameof(dataToVerify)}, {nameof(signedData)} ]"
                );

            if (key?.Public == null)
                throw new ArgumentNullException(
                    message: "Public key must not be null.",
                    paramName: nameof(key)
                );

            if (dataToVerify.Count != signedData.Count)
                return false;

            using (var rsa = new RSACryptoServiceProvider(key.KeySize))
            {
                using (var sha1 = new SHA1CryptoServiceProvider())
                {
                    try
                    {
                        var rsaParams = key.ToRSAParameters(false);
                        rsa.ImportParameters(rsaParams);

                        var verifyAsList = dataToVerify.ToList();
                        var signedAsList = signedData.ToList();

                        for (int i = 0; i < dataToVerify.Count; i++)
                        {
                            if (!rsa.VerifyData(verifyAsList[i], sha1, signedAsList[i]))
                                return false;
                        }

                        return true;
                    }
                    catch (ArgumentNullException ex)
                    {
                        ex.Data["params"] = new List<object> { key };
                        throw;
                    }
                    catch (MissingFieldException ex)
                    {
                        ex.Data["params"] = new List<object> { key };
                        throw;
                    }
                    catch (CryptographicException ex)
                    {
                        ex.Data["params"] = new List<object> { key };
                        throw;
                    }
                    catch (Exception ex)
                    {
                        ex.Data["params"] = new List<object> { dataToVerify, signedData, key };
                        throw;
                    }
                    finally
                    {
                        rsa.PersistKeyInCsp = false;
                    }
                }
            }
        }

        /// <summary>
        /// Decrypt data with the <see cref="System.Security.Cryptography.RSA" /> algorithm.
        /// </summary>
        /// <param name="encryptedData">Encrypted data.</param>
        /// <param name="privKey">Private key.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">Any of the parameters are null</exception>
        /// <exception cref="MissingFieldException">Missing fields on key.</exception>
        /// <exception cref="CryptographicException">Invalid key.</exception>
        public static ICollection<byte[]> Decrypt(ICollection<byte[]> encryptedData, EncryptionPairKey privKey)
        {
            if (encryptedData?.Count == 0)
                throw new ArgumentNullException(
                    message: "At least one data must be available.",
                    paramName: nameof(encryptedData)
                );

            if (privKey?.Private == null)
                throw new ArgumentNullException(
                    message: "Private key must not be null.",
                    paramName: nameof(privKey)
                );

            using (var rsa = new RSACryptoServiceProvider(privKey.KeySize))
            {
                try
                {
                    var rsaParams = privKey.ToRSAParameters(true);
                    var decryptedData = new List<byte[]>();
                    rsa.ImportParameters(rsaParams);

                    foreach (var data in encryptedData)
                        decryptedData.Add(rsa.Decrypt(data, false));

                    return decryptedData;
                }
                catch (ArgumentNullException ex)
                {
                    ex.Data["params"] = new List<object> { privKey };
                    throw;
                }
                // invalid private key
                catch (CryptographicException ex)
                {
                    ex.Data["params"] = new List<object> { privKey };
                    throw;
                }
                catch (MissingFieldException ex)
                {
                    ex.Data["params"] = new List<object> { privKey };
                    throw;
                }
                catch (Exception ex)
                {
                    ex.Data["params"] = new List<object> { encryptedData, privKey };
                    throw;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
}