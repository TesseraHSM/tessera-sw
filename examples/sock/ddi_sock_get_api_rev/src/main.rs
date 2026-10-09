// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Query the API revision with `tsra_ddi_sock_get_api_rev [ENDPOINT] [COUNT]`.
//! The endpoint defaults to `vsock://4:1234`; Unix socket paths also work.

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tsra_ddi_interface::Ddi;
    use tsra_ddi_interface::DdiDev;
    use tsra_ddi_mbor_types::DdiGetApiRevCmdReq;
    use tsra_ddi_mbor_types::DdiGetApiRevCmdResp;
    use tsra_ddi_mbor_types::DdiGetApiRevReq;
    use tsra_ddi_mbor_types::DdiOp;
    use tsra_ddi_mbor_types::DdiReqHdr;
    use tsra_ddi_sock::DdiSock;

    let mut args = std::env::args().skip(1);
    let endpoint = args.next().unwrap_or_else(|| "vsock://4:1234".to_owned());
    let count = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| format!("invalid request count: {error}"))?
        .unwrap_or(1);
    if count == 0 {
        return Err("request count must be greater than zero".into());
    }
    if args.next().is_some() {
        return Err("usage: tsra_ddi_sock_get_api_rev [ENDPOINT] [COUNT]".into());
    }

    let dev = DdiSock::default().open_dev(&endpoint)?;
    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetApiRev,
            sess_id: None,
            rev: None,
        },
        data: DdiGetApiRevReq {},
        ext: None,
    };

    for index in 1..=count {
        let resp: DdiGetApiRevCmdResp = dev.exec_op_mbor(&req, &mut None)?;
        if count == 1 {
            println!(
                "GetApiRev succeeded: min={}.{} max={}.{}",
                resp.data.min.major, resp.data.min.minor, resp.data.max.major, resp.data.max.minor
            );
        } else {
            println!(
                "GetApiRev {index}/{count} succeeded: min={}.{} max={}.{}",
                resp.data.min.major, resp.data.min.minor, resp.data.max.major, resp.data.max.minor
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("the DDI socket tool requires a Unix target".into())
}
