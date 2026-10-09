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

\pagebreak