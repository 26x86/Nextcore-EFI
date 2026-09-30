//! Exact Boot KC input binding for the direct staged-KC research route.

use alloc::{format, vec::Vec};
use nextcore_core::selected_boot_input::{
    parse_selected_bootkc_record, verify_selected_image, verify_selected_record_digest,
    SelectedBootRecord,
    MAX_SELECTED_BOOTKC_BYTES, MAX_SELECTED_IMAGE_BYTES, MAX_SELECTED_RECORD_BYTES,
};
use uefi::{cstr16, CString16, Status};

use crate::firmware_io::{read_file, report};

mod build_seal {
    include!(concat!(env!("OUT_DIR"), "/selected_bootkc_seal.rs"));
}

pub fn load(selected: &SelectedBootRecord, configured_path: &str) -> Result<Vec<u8>, Status> {
    let Some(expected_record_digest) = build_seal::SELECTED_BOOTKC_RECORD_SHA256 else {
        report("NXARMJIT: SELECTED_BOOTKC_RECORD_UNSEALED");
        return Err(Status::NOT_READY);
    };
    let record_bytes = read_file(
        cstr16!("\\EFI\\NextCore\\selected-bootkc.txt"),
        MAX_SELECTED_RECORD_BYTES as u64,
    )?;
    verify_selected_record_digest(Some(expected_record_digest), &record_bytes).map_err(
        |error| {
            report(&format!(
                "NXARMJIT: SELECTED_BOOTKC_RECORD_SEAL_INVALID reason={error:?}"
            ));
            Status::COMPROMISED_DATA
        },
    )?;
    let record = parse_selected_bootkc_record(&record_bytes).map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_BOOTKC_RECORD_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    if !record.matches_selected_path(selected, configured_path) {
        report("NXARMJIT: SELECTED_BOOTKC_BINDING_INVALID");
        return Err(Status::COMPROMISED_DATA);
    }
    let signed_path =
        CString16::try_from(record.signed_path()).map_err(|_| Status::COMPROMISED_DATA)?;
    let signed = read_file(&signed_path, MAX_SELECTED_IMAGE_BYTES as u64)?;
    verify_selected_image(Some(record.signed()), &signed).map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_BOOTKC_SIGNED_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    let decoded_path =
        CString16::try_from(record.decoded_path()).map_err(|_| Status::COMPROMISED_DATA)?;
    let decoded = read_file(&decoded_path, MAX_SELECTED_BOOTKC_BYTES as u64)?;
    verify_selected_image(Some(record.decoded()), &decoded).map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_BOOTKC_DECODED_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    report(&format!(
        "NXARMJIT: SELECTED_BOOTKC_BOUND signed_bytes={} decoded_bytes={} entry_abi=false",
        signed.len(),
        decoded.len()
    ));
    Ok(decoded)
}
