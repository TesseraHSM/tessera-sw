# pkcs11test names off the include-list

Written by `offlist.sh` from an unfiltered pkcs11test run
(2cbe462c62ba, with the fixture patches) against the
emulator module. Do not edit it by hand: change the bucket rules in
`offlist.sh` and run it again.

330 tests: 148 on the include-list, 182 off it (156 fail,
26 pass without asserting anything).

| Bucket | Names | Why they are off the list |
|---|---|---|
| des | 77 | DES or 3DES, which the SDK does not have: the cipher and dual-function fixtures' DES cases, and FindObjectSubset, which generates DES keys and RSA key pairs. |
| aes-ecb | 18 | AES-ECB, out of scope for the module. The two IV cases pass without asserting anything: ECB takes no IV. |
| rsa-keygen | 23 | The fixture generates an RSA key pair. The module does not generate RSA keys: they arrive by unwrap, and the signature cases need an unwrap fixture. |
| hmac | 11 | HMAC keys from CKM_GENERIC_SECRET_KEY_GEN, which the SDK cannot generate. The module's HMAC keys come from ECDH plus HKDF, so these fixtures cannot pass. |
| md5 | 12 | MD5, which the module does not offer. pkcs11test skips these cases. |
| so | 10 | The Security Officer. The device session has one user credential, so CKU_SO is refused and the token is presented initialised. pkcs11test skips the SO logins under -X and token initialisation without -I. |
| rng | 3 | Random numbers. The module has no generator. |
| import | 3 | Plaintext key material through C_CreateObject, which is not a way to make keys on this token. |
| sensitive | 2 | The fixture asks C_GenerateKey for a key with CKA_SENSITIVE=FALSE. Device keys exist only masked, so the token refuses it (CKR_TEMPLATE_INCONSISTENT). |
| unsupported | 19 | Entry points the module does not offer: C_CopyObject, C_DigestKey, C_GetOperationState, the dual-function calls and key wrapping. |
| later | 1 | C_GenerateKeyPair, not implemented yet (it comes with EC key generation). |
| sdk-lag | 2 | SDK behaviour the module cannot change: the CBC stream holds back the last full block until the final call (SDK issue #51), and a wrong PIN is the generic -8 (SDK issue #53), so C_Login cannot answer CKR_PIN_INCORRECT. |
| spec-gap | 1 | Expectations this token does not share: CKR_KEY_TYPE_INCONSISTENT for a mechanism it does not offer, and an error for a NULL mechanism, which PKCS#11 3.0 defines as ending the active operation. |

## des

- `Ciphers/SecretKeyTest.DecryptErrors/0`: fails
- `Ciphers/SecretKeyTest.DecryptErrors/1`: fails
- `Ciphers/SecretKeyTest.DecryptErrors/2`: fails
- `Ciphers/SecretKeyTest.DecryptErrors/3`: fails
- `Ciphers/SecretKeyTest.DecryptFinalErrors1/0`: fails
- `Ciphers/SecretKeyTest.DecryptFinalErrors1/1`: fails
- `Ciphers/SecretKeyTest.DecryptFinalErrors1/2`: fails
- `Ciphers/SecretKeyTest.DecryptFinalErrors1/3`: fails
- `Ciphers/SecretKeyTest.DecryptFinalErrors2/0`: fails
- `Ciphers/SecretKeyTest.DecryptFinalErrors2/1`: fails
- `Ciphers/SecretKeyTest.DecryptFinalErrors2/2`: fails
- `Ciphers/SecretKeyTest.DecryptFinalErrors2/3`: fails
- `Ciphers/SecretKeyTest.DecryptInvalidIV/0`: fails
- `Ciphers/SecretKeyTest.DecryptInvalidIV/1`: fails
- `Ciphers/SecretKeyTest.DecryptInvalidIV/2`: fails
- `Ciphers/SecretKeyTest.DecryptInvalidIV/3`: fails
- `Ciphers/SecretKeyTest.DecryptUpdateErrors/0`: fails
- `Ciphers/SecretKeyTest.DecryptUpdateErrors/1`: fails
- `Ciphers/SecretKeyTest.DecryptUpdateErrors/2`: fails
- `Ciphers/SecretKeyTest.DecryptUpdateErrors/3`: fails
- `Ciphers/SecretKeyTest.EncryptDecrypt/0`: fails
- `Ciphers/SecretKeyTest.EncryptDecrypt/1`: fails
- `Ciphers/SecretKeyTest.EncryptDecrypt/2`: fails
- `Ciphers/SecretKeyTest.EncryptDecrypt/3`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptGetSpace/0`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptGetSpace/1`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptGetSpace/2`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptGetSpace/3`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/0`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/1`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/2`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/3`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptParts/0`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptParts/1`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptParts/2`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptParts/3`: fails
- `Ciphers/SecretKeyTest.EncryptErrors/0`: fails
- `Ciphers/SecretKeyTest.EncryptErrors/1`: fails
- `Ciphers/SecretKeyTest.EncryptErrors/2`: fails
- `Ciphers/SecretKeyTest.EncryptErrors/3`: fails
- `Ciphers/SecretKeyTest.EncryptFailDecrypt/0`: fails
- `Ciphers/SecretKeyTest.EncryptFailDecrypt/1`: fails
- `Ciphers/SecretKeyTest.EncryptFailDecrypt/2`: fails
- `Ciphers/SecretKeyTest.EncryptFailDecrypt/3`: fails
- `Ciphers/SecretKeyTest.EncryptFinalErrors1/0`: fails
- `Ciphers/SecretKeyTest.EncryptFinalErrors1/1`: fails
- `Ciphers/SecretKeyTest.EncryptFinalErrors1/2`: fails
- `Ciphers/SecretKeyTest.EncryptFinalErrors1/3`: fails
- `Ciphers/SecretKeyTest.EncryptFinalErrors2/0`: fails
- `Ciphers/SecretKeyTest.EncryptFinalErrors2/1`: fails
- `Ciphers/SecretKeyTest.EncryptFinalErrors2/2`: fails
- `Ciphers/SecretKeyTest.EncryptFinalErrors2/3`: fails
- `Ciphers/SecretKeyTest.EncryptFinalImmediate/0`: fails
- `Ciphers/SecretKeyTest.EncryptFinalImmediate/1`: fails
- `Ciphers/SecretKeyTest.EncryptFinalImmediate/2`: fails
- `Ciphers/SecretKeyTest.EncryptFinalImmediate/3`: fails
- `Ciphers/SecretKeyTest.EncryptInvalidIV/0`: fails
- `Ciphers/SecretKeyTest.EncryptInvalidIV/1`: fails
- `Ciphers/SecretKeyTest.EncryptInvalidIV/2`: fails
- `Ciphers/SecretKeyTest.EncryptInvalidIV/3`: fails
- `Ciphers/SecretKeyTest.EncryptModePolicing1/0`: fails
- `Ciphers/SecretKeyTest.EncryptModePolicing1/1`: fails
- `Ciphers/SecretKeyTest.EncryptModePolicing1/2`: fails
- `Ciphers/SecretKeyTest.EncryptModePolicing1/3`: fails
- `Ciphers/SecretKeyTest.EncryptModePolicing2/0`: fails
- `Ciphers/SecretKeyTest.EncryptModePolicing2/1`: fails
- `Ciphers/SecretKeyTest.EncryptModePolicing2/2`: fails
- `Ciphers/SecretKeyTest.EncryptModePolicing2/3`: fails
- `Ciphers/SecretKeyTest.EncryptUpdateErrors/0`: fails
- `Ciphers/SecretKeyTest.EncryptUpdateErrors/1`: fails
- `Ciphers/SecretKeyTest.EncryptUpdateErrors/2`: fails
- `Ciphers/SecretKeyTest.EncryptUpdateErrors/3`: fails
- `Duals/DualSecretKeyTest.DigestEncrypt/0`: fails
- `Duals/DualSecretKeyTest.DigestEncrypt/1`: fails
- `Duals/DualSecretKeyTest.DigestEncrypt/2`: fails
- `Duals/DualSecretKeyTest.DigestEncrypt/3`: fails
- `ReadWriteSessionTest.FindObjectSubset`: fails

## aes-ecb

- `Ciphers/SecretKeyTest.DecryptErrors/4`: fails
- `Ciphers/SecretKeyTest.DecryptFinalErrors1/4`: fails
- `Ciphers/SecretKeyTest.DecryptFinalErrors2/4`: fails
- `Ciphers/SecretKeyTest.DecryptInvalidIV/4`: passes, asserts nothing
- `Ciphers/SecretKeyTest.DecryptUpdateErrors/4`: fails
- `Ciphers/SecretKeyTest.EncryptDecrypt/4`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptGetSpace/4`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/4`: fails
- `Ciphers/SecretKeyTest.EncryptDecryptParts/4`: fails
- `Ciphers/SecretKeyTest.EncryptErrors/4`: fails
- `Ciphers/SecretKeyTest.EncryptFailDecrypt/4`: fails
- `Ciphers/SecretKeyTest.EncryptFinalErrors1/4`: fails
- `Ciphers/SecretKeyTest.EncryptFinalErrors2/4`: fails
- `Ciphers/SecretKeyTest.EncryptFinalImmediate/4`: fails
- `Ciphers/SecretKeyTest.EncryptInvalidIV/4`: passes, asserts nothing
- `Ciphers/SecretKeyTest.EncryptModePolicing1/4`: fails
- `Ciphers/SecretKeyTest.EncryptModePolicing2/4`: fails
- `Ciphers/SecretKeyTest.EncryptUpdateErrors/4`: fails

## rsa-keygen

- `KeyPairTest.EncryptDecrypt`: fails
- `ReadOnlySessionTest.SignVerifyRecover`: fails
- `ReadWriteSessionTest.AsymmetricTokenKeyPair`: fails
- `ReadWriteSessionTest.ExtractKeys`: fails
- `ReadWriteSessionTest.PublicExponent4Bytes`: fails
- `Signatures/SignTest.SignFailVerifyShort/0`: fails
- `Signatures/SignTest.SignFailVerifyShort/1`: fails
- `Signatures/SignTest.SignFailVerifyShort/2`: fails
- `Signatures/SignTest.SignFailVerifyShort/3`: fails
- `Signatures/SignTest.SignFailVerifyShort/4`: fails
- `Signatures/SignTest.SignFailVerifyShort/5`: fails
- `Signatures/SignTest.SignFailVerifyWrong/0`: fails
- `Signatures/SignTest.SignFailVerifyWrong/1`: fails
- `Signatures/SignTest.SignFailVerifyWrong/2`: fails
- `Signatures/SignTest.SignFailVerifyWrong/3`: fails
- `Signatures/SignTest.SignFailVerifyWrong/4`: fails
- `Signatures/SignTest.SignFailVerifyWrong/5`: fails
- `Signatures/SignTest.SignVerify/0`: fails
- `Signatures/SignTest.SignVerify/1`: fails
- `Signatures/SignTest.SignVerify/2`: fails
- `Signatures/SignTest.SignVerify/3`: fails
- `Signatures/SignTest.SignVerify/4`: fails
- `Signatures/SignTest.SignVerify/5`: fails

## hmac

- `HMACs/HmacTest.SignFailVerify/0`: fails
- `HMACs/HmacTest.SignFailVerify/1`: fails
- `HMACs/HmacTest.SignFailVerify/2`: fails
- `HMACs/HmacTest.SignFailVerify/3`: fails
- `HMACs/HmacTest.SignFailVerify/4`: fails
- `HMACs/HmacTest.SignVerify/0`: fails
- `HMACs/HmacTest.SignVerify/1`: fails
- `HMACs/HmacTest.SignVerify/2`: fails
- `HMACs/HmacTest.SignVerify/3`: fails
- `HMACs/HmacTest.SignVerify/4`: fails
- `ReadOnlySessionTest.HmacTestVectors`: fails

## md5

- `Digests/DigestTest.CompareIncremental/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestFinalGetSpace/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestFinalIntersperse/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestFinalInvalid/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestGetSpace/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestIntersperse/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestInvalid/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestInvalidSession/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestKey/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestKeyInvalid/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestUpdateInvalidSession/0`: skipped by pkcs11test
- `Digests/DigestTest.DigestUpdateZeroLen/0`: skipped by pkcs11test

## so

- `PKCS11Test.TokenInit`: skipped by pkcs11test
- `PKCS11Test.TokenInitInvalidSlot`: skipped by pkcs11test
- `PKCS11Test.TokenInitPinIncorrect`: skipped by pkcs11test
- `RWSOSessionTest.SOSessionFail`: fails
- `RWSOSessionTest.UserLoginFail`: fails
- `RWUserSessionTest.SOLoginFail`: fails
- `ReadOnlySessionTest.SOLoginFail`: skipped by pkcs11test
- `ReadOnlySessionTest.TokenInitWithSession`: skipped by pkcs11test
- `ReadWriteSessionTest.ReadOnlySessionSOLoginFail`: skipped by pkcs11test
- `ReadWriteSessionTest.SOLogin`: skipped by pkcs11test

## rng

- `ReadOnlySessionTest.GenerateRandomBadArguments`: fails
- `ReadOnlySessionTest.GenerateRandomNone`: passes, asserts nothing
- `ReadOnlySessionTest.SeedRandomBadArguments`: fails

## import

- `ReadOnlySessionTest.CreateKeyPairObjects`: fails
- `ReadOnlySessionTest.CreateSecretKeyAttributes`: fails
- `ReadOnlySessionTest.SecretKeyTestVectors`: fails

## sensitive

- `RWUserSessionTest.TookanAttackA4`: fails
- `RWUserSessionTest.TookanAttackA5b`: fails

## unsupported

- `DataObjectTest.CopyDestroyObjectInvalid`: fails
- `Digests/DigestTest.DigestKey/1`: fails
- `Digests/DigestTest.DigestKey/2`: fails
- `Digests/DigestTest.DigestKey/3`: fails
- `Digests/DigestTest.DigestKey/4`: fails
- `Digests/DigestTest.DigestKeyInvalid/1`: fails
- `Digests/DigestTest.DigestKeyInvalid/2`: fails
- `Digests/DigestTest.DigestKeyInvalid/3`: fails
- `Digests/DigestTest.DigestKeyInvalid/4`: fails
- `Duals/DualSecretKeyTest.DigestEncrypt/4`: skipped by pkcs11test
- `Duals/DualSecretKeyTest.DigestEncrypt/5`: skipped by pkcs11test
- `ROUserSessionTest.UnwrapInvalid`: fails
- `ROUserSessionTest.WrapInvalid`: fails
- `ROUserSessionTest.WrapUnwrap`: fails
- `RWEitherSessionTest.TookanAttackA2`: fails
- `ReadWriteSessionTest.CreateCopyDestroyObject`: fails
- `ReadWriteSessionTest.GetSetOperationState`: skipped by pkcs11test
- `ReadWriteSessionTest.GetSetOperationStateInvalid`: skipped by pkcs11test
- `ReadWriteSessionTest.TookanAttackA1`: fails

## later

- `ReadOnlySessionTest.GenerateKeyPairInvalid`: fails

## sdk-lag

- `Ciphers/SecretKeyTest.EncryptDecryptParts/5`: fails
- `ReadOnlySessionTest.UserLoginWrongPIN`: fails

## spec-gap

- `Ciphers/SecretKeyTest.EncryptDecryptInitInvalid/5`: fails
