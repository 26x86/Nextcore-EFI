//! Exact selected companion ingress and research-only physical staging.

use alloc::{format, vec::Vec};
use nextcore_core::selected_boot_input::{
    parse_selected_startup_companions, verify_selected_image, verify_selected_record_digest,
    SelectedBootRecord, SelectedCompanion, MAX_SELECTED_IMAGE_BYTES, MAX_SELECTED_RECORD_BYTES,
};
use nextcore_core::{
    arm64_stage1_tables::Stage1Alias,
    arm64_startup_image::stage_startup_images,
};
use uefi::{cstr16, CString16, Status};

use crate::firmware_io::{read_file, report};

mod build_seal {
    include!(concat!(env!("OUT_DIR"), "/selected_startup_seal.rs"));
}

pub struct OwnedCompanions {
    _sptm: Vec<u8>,
    _txm: Vec<u8>,
}

impl OwnedCompanions {
    pub fn stage_into_guest(
        &self,
        physical_base: u64,
        occupied_end: u64,
        guest_ram: &mut [u8],
    ) -> Result<[Stage1Alias; 2], Status> {
        let placed = stage_startup_images(
            &self._sptm,
            &self._txm,
            physical_base,
            occupied_end,
            guest_ram,
        )
        .map_err(|error| {
            report(&format!(
                "NXARMJIT: SELECTED_STARTUP_PLACEMENT_INVALID reason={error:?}"
            ));
            Status::COMPROMISED_DATA
        })?;
        report(&format!(
            "NXARMJIT: SELECTED_STARTUP_PHYSICAL sptm_base={:#x} sptm_bytes={} txm_base={:#x} txm_bytes={} linked_va_mapped=false entry_abi=false",
            placed.sptm.physical_base,
            placed.sptm.bytes,
            placed.txm.physical_base,
            placed.txm.bytes,
        ));
        Ok([
            Stage1Alias {
                virtual_base: placed.sptm.virtual_base,
                physical_base: placed.sptm.physical_base,
                bytes: placed.sptm.bytes as u64,
            },
            Stage1Alias {
                virtual_base: placed.txm.virtual_base,
                physical_base: placed.txm.physical_base,
                bytes: placed.txm.bytes as u64,
            },
        ])
    }
}

fn read_companion(role: &str, record: &SelectedCompanion) -> Result<Vec<u8>, Status> {
    let signed_path =
        CString16::try_from(record.signed_path()).map_err(|_| Status::COMPROMISED_DATA)?;
    let signed = read_file(&signed_path, MAX_SELECTED_IMAGE_BYTES as u64)?;
    verify_selected_image(Some(record.signed()), &signed).map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_{role}_SIGNED_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    let decoded_path =
        CString16::try_from(record.decoded_path()).map_err(|_| Status::COMPROMISED_DATA)?;
    let decoded = read_file(&decoded_path, MAX_SELECTED_IMAGE_BYTES as u64)?;
    verify_selected_image(Some(record.decoded()), &decoded).map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_{role}_DECODED_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    report(&format!(
        "NXARMJIT: SELECTED_{role}_BOUND signed_bytes={} decoded_bytes={} runtime_mapped=false",
        signed.len(),
        decoded.len()
    ));
    Ok(decoded)
}

pub fn load(selected: &SelectedBootRecord) -> Result<OwnedCompanions, Status> {
    let Some(seal) = build_seal::SELECTED_STARTUP_RECORD_SHA256 else {
        report("NXARMJIT: SELECTED_STARTUP_RECORD_UNSEALED");
        return Err(Status::NOT_READY);
    };
    let bytes = read_file(
        cstr16!("\\EFI\\NextCore\\selected-startup.txt"),
        MAX_SELECTED_RECORD_BYTES as u64,
    )?;
    verify_selected_record_digest(Some(seal), &bytes).map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_STARTUP_RECORD_SEAL_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    let record = parse_selected_startup_companions(&bytes).map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_STARTUP_RECORD_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    if !record.binds_selected(selected) || !record.paths_disjoint_from(&[selected.image_path()]) {
        report("NXARMJIT: SELECTED_STARTUP_BINDING_INVALID");
        return Err(Status::COMPROMISED_DATA);
    }
    let sptm = read_companion("SPTM", record.sptm())?;
    let txm = read_companion("TXM", record.txm())?;
    report("NXARMJIT: SELECTED_STARTUP_OWNED runtime_mapped=false entry_abi=false");
    Ok(OwnedCompanions {
        _sptm: sptm,
        _txm: txm,
    })
}
