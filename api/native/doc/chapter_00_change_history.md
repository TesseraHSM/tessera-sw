# Change History


| Date       | Description                                               &nbsp; |
| ---------- | ---------------------------------------------------------------- |
| 04/02/2025 | Document Created                                                 |
| 04/10/2025 | Integrated feedback from Bryan Kelly                             |
| 04/29/2025 | Integrated feedback from Rajesh Gali                             |
| 05/01/2025 | Added API to retrieve certificate chains                         |
|            | Added API to provision partition owner certificate               |
|            | Added Key property to retrieve masked key                        |
|            | Added Session kind support                                       |
|            | Renamed device API to partition API                              |
| 05/12/2025 | Fixed parameter type for partition get API                       |
|            | Fixed parameter name for partition get path API                  |
| 12/09/2025 | Updated algorithm parameter for AES CBC                          |
|            | Added data unit length param to algorithm parameter for AES XTS  |
| 04/02/2026 | Replaced `tsra_part_get_path` with `tsra_part_get_info`     |
|            | Added `tsra_part_info` structure with API revision range       |
|            | Added `api_rev` parameter to `tsra_part_open`                 |
|            | Removed `api_rev` parameter from `tsra_sess_open`             |
|            | Added `TSRA_STATUS_UNSUPPORTED_API_REVISION` error code       |
| 07/08/2026 | Added Security Domain API chapter (`tsra_sess_ex_open`,        |
|            | `tsra_sess_ex_part_init`)                                      |
|            | Added `tsra_session_ex_type` enum                              |
| 08/27/2026 | Added `TSRA_STATUS_UNSUPPORTED_KEY_OPERATION` error code       |
| 09/13/2026 | Added DARC key-transfer API chapter (`tsra_darc_kex_key_gen`,  |
|            | `tsra_darc_tmk_gen`, `tsra_darc_tmk_export`,                 |
|            | `tsra_darc_tmk_import`, `tsra_darc_key_wrap`,                |
|            | `tsra_darc_key_unwrap`)                                        |
| 09/23/2026 | Reworked `tsra_darc_key_wrap`/`tsra_darc_key_unwrap` to the  |
|            | handle/algo model: wrap takes a source key handle, unwrap        |
|            | returns recovered private/public key handles                     |
| 10/01/2026 | Added partition-policy builder (`tsra_part_policy_builder_new`, |
|            | setters, `tsra_part_policy_build`, `_free`)                    |
| 10/31/2026 | Added AES ECB, CFB, OFB and CTR algorithms (`TSRA_ALGO_ID_AES_ECB`, |
|            | `TSRA_ALGO_ID_AES_CFB`, `TSRA_ALGO_ID_AES_OFB`,                  |
|            | `TSRA_ALGO_ID_AES_CTR`) and their parameter structures           |
|            | AES-XTS `tsra_key_unwrap` on ex sessions takes a single wrap of  |
|            | the 64-byte `K1 \|\| K2` key                                     |
|            | AES-XTS on ex sessions supports a 64-bit tweak; non-zero upper   |
|            | `sector_num` bytes return `TSRA_STATUS_INVALID_TWEAK`            |
|            | `tsra_key_unmask_pair` supports RSA and ECC on ex sessions       |
|            | `tsra_key_unmask` authenticates the blob on ex sessions (TBOR    |
|            | `VerifyKey`); tampered or wrong-session blobs fail at unmask     |
| 11/11/2026 | Added API revision 2.0 (Duo): only `tsra_sess_ex_open` sessions, |
|            | with encrypted session transport; `tsra_part_init` and           |
|            | `tsra_sess_open` are not supported at 2.0                        |
|            | `TSRA_PART_PROP_ID_BACKUP_MASKING_KEY` and                       |
|            | `TSRA_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY` are not present on   |
|            | partitions provisioned with `tsra_sess_ex_part_init`             |
| 11/13/2026 | Partition policy is a deterministic CBOR document (at most 384   |
|            | bytes) naming keys by SPKI SHA-384 thumbprint                    |
|            | `tsra_part_policy_build` emits the CBOR document; key setters    |
|            | take a `tsra_policy_key_format`; removed                         |
|            | `tsra_part_policy_builder_set_version`; renamed                  |
|            | `set_backup_part_pub_key` to `set_backup_part_key`               |
|            | Added `tsra_part_policy_builder_set_data_key` and                |
|            | `tsra_policy_key_thumbprint`                                     |
|            | Removed `pota_thumbprint`, `sata_thumbprint` and                 |
|            | `sapota_thumbprint` from `tsra_sess_ex_part_init_params`         |

\pagebreak