// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(not(test), no_main)]

#[path = "../../mbor_requests.rs"]
mod requests;

use std::sync::LazyLock;

use libfuzzer_sys::Corpus;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_mbor_types::DdiReqHdr;
use tsra_ddi_mbor_types::SessionInfoRequest;
use tsra_fw_hsm_io::CmdDword;
use tsra_fw_hsm_io::OP_MBOR;
use tsra_fw_hsm_io::SessionFlags;
use tsra_fw_hsm_io::SqeBuilder;
use tsra_fw_hsm_std_uno::StdHsm;

use crate::requests::get_rand_ddi_request;
use crate::requests::RequestBuffers;

const PAGE_LEN: usize = 4096;
const DMA_LEN: usize = 2 * PAGE_LEN;

#[repr(align(4096))]
struct DmaBuffer([u8; DMA_LEN]);

struct Dispatcher {
    hsm: StdHsm,
    runtime: tokio::runtime::Runtime,
}

impl Dispatcher {
    fn new() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to create firmware runtime");
        let hsm = StdHsm::with_tokio(runtime.handle().clone());
        Self { hsm, runtime }
    }

    fn dispatch(&self, session: SessionInfoRequest, data: &[u8]) -> ([u32; 4], Box<DmaBuffer>) {
        let mut source = Box::new(DmaBuffer([0; DMA_LEN]));
        let mut destination = Box::new(DmaBuffer([0; DMA_LEN]));
        source.0[..data.len()].copy_from_slice(data);
        let src_addr = source.0.as_ptr() as u64;
        let dst_addr = destination.0.as_mut_ptr() as u64;
        let mut sqe = SqeBuilder::new()
            .cmd(CmdDword::new().with_op(OP_MBOR))
            .buf_lens(data.len() as u32, DMA_LEN as u32)
            .src_prp1(src_addr)
            .dst_prp1(dst_addr)
            .session_flags(
                SessionFlags::new()
                    .with_ctrl(session.session_control_kind.into())
                    .with_id_valid(session.session_id.is_some()),
            )
            .session_id(session.session_id.unwrap_or_default())
            .build();
        sqe[4] = (src_addr + PAGE_LEN as u64) as u32;
        sqe[5] = ((src_addr + PAGE_LEN as u64) >> 32) as u32;
        sqe[9] = (dst_addr + PAGE_LEN as u64) as u32;
        sqe[10] = ((dst_addr + PAGE_LEN as u64) >> 32) as u32;

        let completion = self.runtime.block_on(async {
            // Recreate the legacy simulator's fresh four-resource partition per input.
            self.hsm
                .part_alloc(0, 0b1111)
                .await
                .expect("Allocate partition");
            self.hsm.part_enable(0).await.expect("Enable partition");
            // Both aligned DMA buffers remain owned here until IO has completed.
            let completion = self.hsm.io(sqe, 0, 0, 0).await.expect("Firmware IO failed");
            assert!((completion[0] & 0xFFFF) as usize <= DMA_LEN);
            self.hsm.part_disable(0).await.expect("Disable partition");
            self.hsm.part_free(0).await.expect("Free partition");
            completion
        });
        (completion, destination)
    }
}

static DISPATCHER: LazyLock<Dispatcher> = LazyLock::new(Dispatcher::new);

/// A struct containing several fields to adjust the manner in which this fuzz
/// target executes.
#[derive(Debug, Arbitrary, Clone)]
struct FuzzInput {
    /// Randomized session metadata supplied directly to firmware.
    session_info_request: SessionInfoRequest,

    /// Random bytes that are passed into the firmware dispatcher if
    /// `use_rand_data` is set to `true`.
    rand_data: Vec<u8>,

    /// If set to `true`, the fuzzing target will feed `rand_data` directly into
    /// the firmware dispatcher. If set to `false`, the below fields will be
    /// used to construct a valid, random header and DDI request object that is
    /// fed into the firmware dispatcher.
    use_rand_data: bool,

    /// A seed with which a random DDI request object will be generated.
    ///
    /// If `use_rand_data` is set to `false`, this will instead be used to
    /// generate a valid, but random, DDI request object to pass into
    /// the dispatcher. By using an actual DDI request object instead of a fully
    /// random buffer (`rand_data`), we make it easier for the fuzzer to explore
    /// the "valid header" execution space, which could allow the fuzzer to
    /// discover more behavior deeper within the firmware.
    ///
    /// This also allows us to fuzz MBOR encoding, since we'll be encoding a
    /// randomly-generated header & request object before passing it to
    /// the dispatcher.
    request_seed: u64,

    /// A DDI request header, to be used along with `request_seed`.
    request_header: DdiReqHdr,
}

fuzz_target!(|input: FuzzInput| -> Corpus {
    let data = if input.use_rand_data {
        input.rand_data
    } else {
        let mut _rbuf = RequestBuffers::default();
        match get_rand_ddi_request(input.request_header, input.request_seed, &mut _rbuf) {
            Ok(data) => data,
            Err(_) => return Corpus::Keep,
        }.to_vec()
    };
    if data.len() > DMA_LEN {
        return Corpus::Reject;
    }
    let _ = DISPATCHER.dispatch(input.session_info_request, &data);
    Corpus::Keep
});

#[cfg(test)]
mod tests {
    use tsra_ddi_mbor_types::DdiDecoder;
    use tsra_ddi_mbor_types::DdiGetApiRevResp;
    use tsra_ddi_mbor_types::DdiOp;
    use tsra_ddi_mbor_types::DdiRespHdr;
    use tsra_ddi_mbor_types::DdiStatus;

    use super::*;

    #[test]
    fn dispatches_mbor_without_transport_and_resets_between_inputs() {
        let mut buffers = RequestBuffers::default();
        let request = requests::TestDdiReqs::GetApiRev
            .encode(
                DdiReqHdr {
                    op: DdiOp::GetApiRev,
                    rev: None,
                    sess_id: None,
                },
                0,
                true,
                &mut buffers,
            )
            .expect("Encode API revision request")
            .to_vec();
        for data in [
            request.as_slice(),
            &[0xFF; PAGE_LEN + 1],
            request.as_slice(),
        ] {
            let (completion, response) = DISPATCHER.dispatch(SessionInfoRequest::default(), data);
            if data == request {
                let len = (completion[0] & 0xFFFF) as usize;
                let mut decoder = DdiDecoder::new(&response.0[..len], false);
                let header: DdiRespHdr = decoder.decode_hdr().expect("Firmware MBOR response");
                assert_eq!(header.status, DdiStatus::Success);
                let _ = decoder
                    .decode_data::<DdiGetApiRevResp>()
                    .expect("API revision");
            }
        }
    }
}
