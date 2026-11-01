# Attestation Operation

## tsra_generate_key_report

Retrieve the attestation report for a specified key

TBOR `KeyReport` is available to active Crypto Officer and Crypto User
sessions on a finalized partition. The calling role's default PSK must be
rotated, and the masked key must pass its scope and authentication checks.
The session must have authenticated with the current TBOR credential.
The SDK authenticates the masked key and report data with the session's
parameter key; CU requests without this proof are rejected. Ordinary key
attestation does not authorize using that key as an SD backup recipient.

```cpp
const tsra_byte *tsra_generate_key_report(
    tsra_handle key_handle, 
    const tsra_buffer *report_data,
    tsra_buffer *report
    );
```
**Parameters**

| Parameter        | Name                        | Description                                                 |
| ---------------- | --------------------------- | ----------------------------------------------------------- |
| [in] key_handle  | [tsra_handle](#tsra_handle)   | key handle to attest                                        |
| [in] report_data | [tsra_buffer*](#tsra_buffer)  | exactly 128 bytes of additional data to be included in report |
| [in, out] report | [tsra_buffer *](#tsra_buffer) | attestation report for the key                               |

**Returns**

 `TSRA_STATUS_SUCCESS` on success, error code otherwise
 