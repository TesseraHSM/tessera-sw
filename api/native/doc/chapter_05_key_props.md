# Key Properties

Keys are created in the device via following operations:

- Symmetric Key Generation API
- Asymmetric Key Generation API
- Key Unwrap API
- Key Derivation API

During key creation time, application can modify the the keys usage, applicability 
and behavior part by setting properties on the key. Following are the properties
supported on the key:

## Class

Key class defines the classification of the key.  Possible classes are:

- Private
- Public
- Secret

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Define      | TSRA_KEY_PROP_ID_CLASS                                       |
| Type        | [tsra_key_class](#tsra_key_class)                            |
| Values      | [TSRA_KEY_CLASS_XXX](#tsra_key_class_xxx)                    |
| Default     | Automatically set by key generation algorithm         &nbsp; |
| Applicable  | All Keys                                                     |
| Specifiable | No                                                           |
| PKCS#11     | CKA_CLASS                                                    |



## Type

Defines the type of the key. Possible key types are:

- RSA
- EC
- AES
- AES-XTS
- AES-GCM
- Generic
- HMAC-SHA1
- HMAC-SHA256
- HMAC-SHA384
- HMAC-SHA512
- Masking

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Define      | TSRA_KEY_PROP_ID_TYPE                                        |
| Type        | [tsra_key_type](#tsra_key_type)                              |
| Values      | [TSRA_KEY_TYPE_XXX](#tsra_key_type_xxx)                      |
| Default     | Set by caller during key creation                     &nbsp; |
| Applicable  | All Keys                                                     |
| Specifiable | Yes                                                          |
| PKCS#11     | CKA_TYPE                                                     |


## Bit Length

Defines the length of the key in bits

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Define      | TSRA_KEY_PROP_ID_BIT_LEN                                     |
| Type        | [tsra_u32](#tsra_u32)                                        |
| Values      | Any valid value of tsra_u32 > 0                              |
| Default     | Set by caller during key creation                     &nbsp; |
| Applicable  | All Keys                                                     |
| Specifiable | Yes                                                          |
| PKCS#11     | CKA_VALUE_LEN,CKA_MODULUS_BITS                               |

## Label

Label associated with the key

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Define      | TSRA_KEY_PROP_ID_LABEL                                       |
| Type        | [tsra_utf8_char *](#tsra_utf8_char)                          |
| Values      | Any valid utf-8 string < 128 bytes                           |
| Default     | Set by caller during key creation                     &nbsp; |
| Applicable  | All Keys                                                     |
| Specifiable | Yes                                                          |
| PKCS#11     | CKA_LABEL                                                    |

## Session 

Flag indicating if the key is a session key

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Define      | TSRA_KEY_PROP_ID_SESSION                                     |
| Type        | [tsra_bool](#tsra_bool)                                      |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                              |
| Default     | [TSRA_BOOL_TRUE](#tsra_bool)                      &nbsp;     |
| Applicable  | All Keys                                                     |
| Specifiable | Yes                                                          |
| PKCS#11     | CKA_TOKEN                                                    |

## Private Key

Flag indicating the key is private or not. If the key is private an authenticated
session using [tsra_sess_open](#open-session) must be established.

All keys generated within the session are private. This flag is set by the device
for keys that can be accessed with establishing a session

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Define      | TSRA_KEY_PROP_ID_PRIVATE                                     |
| Type        | [tsra_bool](#tsra_bool)                                      |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                              |
| Default     | [TSRA_BOOL_TRUE](#tsra_bool)                      &nbsp;     |
| Applicable  | All Keys                                                     |
| Specifiable | No                                                           |
| PKCS#11     | CKA_PRIVATE                                                  |


## Modifiable

Flag indicating the key is modifiable or not.

|             |                                                               |
| ----------- | ------------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_MODIFIABLE                                   |
| Type        | [tsra_bool](#tsra_bool)                                       |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                               |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                      &nbsp;     |
| Applicable  | All Keys                                                      |
| Specifiable | Yes                                                           |
| PKCS#11     | CKA_MODIFIABLE                                                |

## Copyable

Flag indicating the key is copyable or not. All keys are not copyable.

|             |                                                               |
| ----------- | ------------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_COPYABLE                                     |
| Type        | [tsra_bool](#tsra_bool)                                       |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                               |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                      &nbsp;     |
| Applicable  | All Keys                                                      |
| Specifiable | No                                                            |
| PKCS#11     | CKA_COPYABLE                                                  |

## Destroyable

Flag indicating the key is destroyable or not. All keys created in a session
are destroyable.

Device generated keys may be marked as not destroyable.

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Define      | TSRA_KEY_PROP_ID_DESTROYABLE                                 |
| Type        | [tsra_bool](#tsra_bool)                                      |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                              |
| Default     | [TSRA_BOOL_TRUE](#tsra_bool)                      &nbsp;     |
| Applicable  | All Keys                                                     |
| Specifiable | No                                                           |
| PKCS#11     | CKA_DESTROYABLE                                              |

## Local

Flag indicating the key is locally generated or imported. The flag is set by 
the device and cannot be changed via the API.


|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Define      | TSRA_KEY_PROP_ID_LOCAL                                       |
| Type        | [tsra_bool](#tsra_bool)                                      |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                              |
| Default     | [TSRA_BOOL_TRUE](#tsra_bool)                      &nbsp;     |
| Applicable  | All Keys                                                     |
| Specifiable | No                                                           |
| PKCS#11     | CKA_LOCAL                                                    |

## Sensitive

Flag indicating the value of the key is not revealed or visible outside the 
device. 

Private and Secret Keys are always sensitive. Public keys are not sensitive.

|             |                                                            |
| ----------- | ---------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_SENSITIVE                                 |
| Type        | [tsra_bool](#tsra_bool)                                    |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                            |
| Default     | [TSRA_BOOL_TRUE](#tsra_bool) for Private & Secret Keys     |
|             | [TSRA_BOOL_FALSE](#tsra_bool) for Public Keys              |
| Applicable  | All Keys                                                   |
| Specifiable | No                                                         |
| PKCS#11     | CKA_SENSITIVE                                              |

## Always Sensitive

Flag indicating the key has always been sensitive (means key has never been
marked not sensitive). 

Private and Secret Keys are always sensitive. Public keys are not sensitive.

|             |                                                            |
| ----------- | ---------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_ALWAYS_SENSITIVE                          |
| Type        | [tsra_bool](#tsra_bool)                                    |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                            |
| Default     | [TSRA_BOOL_TRUE](#tsra_bool) for Private & Secret Keys     |
|             | [TSRA_BOOL_FALSE](#tsra_bool) for Public Keys              |
| Applicable  | All Keys                                                   |
| Specifiable | No                                                         |
| PKCS#11     | CKA_ALWAYS_SENSITIVE                                       |

## Extractable

Flag indicating the value of the key is extractable from the device or not.

All session keys are always extractable. Device generated keys may be marked
as not extractable.

|             |                                                            |
| ----------- | ---------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_EXTRACTABLE                               |
| Type        | [tsra_bool](#tsra_bool)                                    |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                            |
| Default     | [TSRA_BOOL_TRUE](#tsra_bool)                    &nbsp;     |
| Applicable  | All Keys                                                   |
| Specifiable | No                                                         |
| PKCS#11     | CKA_EXTRACTABLE                                            |

## Never Extractable

Flag indicating the key has ever been marked not extractable

All session keys are marked always extractable. Device generated keys may be 
marked as never extractable.

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_NEVER_EXTRACTABLE                          |
| Type        | [tsra_bool](#tsra_bool)                                     |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                             |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                    &nbsp;     |
| Applicable  | All Keys                                                    |
| Specifiable | No                                                          |
| PKCS#11     | CKA_ALWAYS_NEVER_EXTRACTABLE                                |

## Trusted

Flag indicating the key can be trusted to wrap keys. This flag can only be
specified for Public Keys. Private & Shared keys will report this flag as 
not set.

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_TRUSTED                                    |
| Type        | [tsra_bool](#tsra_bool)                                     |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                             |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                    &nbsp;     |
| Applicable  | Public Keys                                                 |
| Specifiable | Yes                                                         |
| PKCS#11     | CKA_ALWAYS_TRUSTED                                          |

## Wrap With Trusted

Flag indicating that a key can only be wrapped with a key that is marked trusted.
This property is applicable to Private and Shared keys.

All private and secret keys generate in session are marked with this property. 

|             |                                                            |
| ----------- | ---------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_WRAP_WITH_TRUSTED                         |
| Type        | [tsra_bool](#tsra_bool)                                    |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                            |
| Default     | [TSRA_BOOL_TRUE](#tsra_bool)                    &nbsp;     |
| Applicable  | Private & Secret Keys                                      |
| Specifiable | No                                                         |
| PKCS#11     | CKA_WRAP_WITH_TRUSTED                                      |

## Encrypt

Flag indicating if the key can be used for encrypt operations. This flag can
be specified only for Public Keys and Secret Keys.

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_ENCRYPT                                    |
| Type        | [tsra_bool](#tsra_bool)                                     |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                             |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                    &nbsp;     |
| Applicable  | Public & Secret Keys                                        |
| Specifiable | Yes                                                         |
| PKCS#11     | CKA_ENCRYPT                                                 |

## Decrypt

Flag indicating if the key can be used for decrypt operations. This flag can
be specified only for Private and Secret Keys.

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_DECRYPT                                    |
| Type        | [tsra_bool](#tsra_bool)                                     |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                             |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                    &nbsp;     |
| Applicable  | Private & Secret Keys                                       |
| Specifiable | Yes                                                         |
| PKCS#11     | CKA_DECRYPT                                                 |

## Sign

Flag indicating if the key can be used for sign operations. This flag can
be specified only for Private Keys and Secret Keys.

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_SIGN                                       |
| Type        | [tsra_bool](#tsra_bool)                                     |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                             |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                    &nbsp;     |
| Applicable  | Private & Secret Keys                                       |
| Specifiable | Yes                                                         |
| PKCS#11     | CKA_SIGN                                                    |

## Verify

Flag indicating if the key can be used for verify operations. This flag can
be specified only for Public and Secret Keys.

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_VERIFY                                     |
| Type        | [tsra_bool](#tsra_bool)                                     |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                             |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                    &nbsp;     |
| Applicable  | Public & Secret Keys                                        |
| Specifiable | Yes                                                         |
| PKCS#11     | CKA_VERIFY                                                  |


## Wrap

Flag indicating if the key can be used for wrap operations. This flag can
be specified only for Public Keys and Secret Keys.

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_WRAP                                       |
| Type        | [tsra_bool](#tsra_bool)                                     |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                             |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                    &nbsp;     |
| Applicable  | Public & Secret Keys                                        |
| Specifiable | Yes                                                         |
| PKCS#11     | CKA_WRAP                                                    |

## Unwrap

Flag indicating if the key can be used for unwrap operations. This flag can
be specified only for Private and Secret Keys.

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_UNWRAP                                     |
| Type        | [tsra_bool](#tsra_bool)                                     |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                             |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                    &nbsp;     |
| Applicable  | Private & Secret Keys                                       |
| Specifiable | Yes                                                         |
| PKCS#11     | CKA_UNWRAP                                                  |

## Derive

Flag indicating if the key can be used for derive operations. This flag can
be specified only for Secret Keys.

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_DERIVE                                     |
| Type        | [tsra_bool](#tsra_bool)                                     |
| Values      | [TSRA_BOOL_XXX](#tsra_bool_xxx)                             |
| Default     | [TSRA_BOOL_FALSE](#tsra_bool)                    &nbsp;     |
| Applicable  | Private & Secret Keys                                       |
| Specifiable | Yes                                                         |
| PKCS#11     | CKA_DERIVE                                                  |


## Public Key Info

DER-encoding of the SubjectPublicKeyInfo for this public key. This property
is available for Public & Private Keys.

|             |                                                                |
| ----------- | -------------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_PUB_KEY_INFO                                     |
| Type        | [tsra_byte *](#tsra_byte)                                      |
| Values      | Any valid DER encoded SubjectPublicKeyInfo                     |
| Default     | Empty                                                   &nbsp; |
| Applicable  | Private & Public Keys                                          |
| Specifiable | Yes                                                            |
| PKCS#11     | CKA_PUBLIC_KEY_INFO                                            |

## EC Curve

The elliptic curve type for the key. This property is only valid for EC
key types. Supported curves are

- P256
- P384
- P521

|             |                                                              |
| ----------- | ------------------------------------------------------------ |
| Define      | TSRA_KEY_PROP_ID_EC_CURVE                                    |
| Type        | [tsra_ec_curve_id](#tsra_ec_curve_id)                        |
| Values      | [TSRA_EC_CURVE_ID_XXX](#tsra_ec_curve_id_xxx)                |
| Default     | Set by caller during key creation                     &nbsp; |
| Applicable  | EC Public & Private Keys                                     |
| Specifiable | Yes                                                          |
| PKCS#11     | CKA_EC_PARAMS                                                |


## Masked Key

The masked or encrypted key associated with the given private or secret key

Masked keys are opaque, variable-length blobs. TBOR GCM masked keys use the
`AesGcm256` algorithm (`0x03`): a 16-byte stored IV, 192-byte authenticated metadata, plaintext
zero-padded to 16 bytes, and a 16-byte tag. The authenticated padding count
preserves the original key length. Only the first 12 IV bytes form the GCM
nonce; the remaining four bytes are ignored when unmasking.

Metadata remains at version 1; the padding count occupies a previously reserved
byte. This format requires matching SDK and firmware updates. Existing
12-byte-IV masked-key blobs and their persisted backups must be regenerated.
GCM parameter envelopes also use the 16-byte IV slot. Legacy CBC masked keys
are unchanged.

|             |                                                             |
| ----------- | ----------------------------------------------------------- |
| Define      | TSRA_KEY_PROP_ID_MASKED_KEY                                 |
| Type        | [tsra_byte *](#tsra_byte)                                   |
| Values      | Byte array containing the masked key                        |
| Default     | Byte array containing the masked key                        |
| Applicable  | Private & Secret Keys                                       |
| Specifiable | No                                                          |
| PKCS#11     | N/A                                                  &nbsp; |

\pagebreak