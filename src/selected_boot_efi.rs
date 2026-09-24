//! EFI reader for a prepared selected iBoot record and its exact image bytes.

use alloc::{format, vec::Vec};
use nextcore_core::selected_boot_input::{
    copy_selected_payload, parse_selected_boot_record, parse_selected_payload_record,
    verify_selected_image, SelectedBootRecord, MAX_SELECTED_IMAGE_BYTES,
    MAX_SELECTED_PAYLOAD_RECORD_BYTES, MAX_SELECTED_RECORD_BYTES,
};
use uefi::{cstr16, CString16, Status};

use crate::arm_pages::ArmPages;
use crate::firmware_io::{read_file, report};

pub struct SelectedBootPayload {
    pages: ArmPages,
    copied_bytes: usize,
}

impl SelectedBootPayload {
    pub fn copied_bytes(&self) -> usize {
        self.copied_bytes
    }

    pub fn allocated_bytes(&self) -> usize {
        self.pages.bytes()
    }
}

/// Keeps the exact checked source bytes owned until a later placement consumes them.
pub struct SelectedBootSource {
    record: SelectedBootRecord,
    image: Vec<u8>,
}

impl SelectedBootSource {
    pub fn record(&self) -> &SelectedBootRecord {
        &self.record
    }

    pub fn image(&self) -> &[u8] {
        &self.image
    }
}

pub fn load() -> Result<SelectedBootSource, Status> {
    let record_bytes = read_file(
        cstr16!("\\EFI\\NextCore\\selected-iboot.txt"),
        MAX_SELECTED_RECORD_BYTES as u64,
    )
    .map_err(|status| {
        report(&format!(
            "NXARMJIT: SELECTED_IBOOT_RECORD_READ_FAILED status={status:?}"
        ));
        Status::NOT_READY
    })?;
    let record = parse_selected_boot_record(&record_bytes).map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_IBOOT_RECORD_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    let path = CString16::try_from(record.image_path()).map_err(|_| Status::COMPROMISED_DATA)?;
    let image = read_file(&path, MAX_SELECTED_IMAGE_BYTES as u64).map_err(|status| {
        report(&format!(
            "NXARMJIT: SELECTED_IBOOT_IMAGE_READ_FAILED status={status:?}"
        ));
        status
    })?;
    verify_selected_image(Some(record.expected()), &image).map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_IBOOT_IMAGE_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    Ok(SelectedBootSource { record, image })
}

pub fn load_payload(source: &SelectedBootSource) -> Result<SelectedBootPayload, Status> {
    let companion_bytes = read_file(
        cstr16!("\\EFI\\NextCore\\selected-iboot-payload.txt"),
        MAX_SELECTED_PAYLOAD_RECORD_BYTES as u64,
    )
    .map_err(|status| {
        report(&format!(
            "NXARMJIT: SELECTED_IBOOT_PAYLOAD_RECORD_READ_FAILED status={status:?}"
        ));
        status
    })?;
    let companion = parse_selected_payload_record(&companion_bytes).map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_IBOOT_PAYLOAD_RECORD_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    let path =
        CString16::try_from(companion.decoded_path()).map_err(|_| Status::COMPROMISED_DATA)?;
    let decoded = read_file(&path, MAX_SELECTED_IMAGE_BYTES as u64).map_err(|status| {
        report(&format!(
            "NXARMJIT: SELECTED_IBOOT_PAYLOAD_READ_FAILED status={status:?}"
        ));
        status
    })?;
    let allocation_bytes = companion
        .expected()
        .byte_len()
        .checked_add(16383)
        .map(|size| size & !16383)
        .ok_or(Status::OUT_OF_RESOURCES)?;
    let mut pages = ArmPages::allocate_data(allocation_bytes)?;
    let copied_bytes = copy_selected_payload(
        source.record(),
        source.image(),
        &companion,
        &decoded,
        pages.bytes_mut(),
    )
    .map_err(|error| {
        report(&format!(
            "NXARMJIT: SELECTED_IBOOT_PAYLOAD_INVALID reason={error:?}"
        ));
        Status::COMPROMISED_DATA
    })?;
    Ok(SelectedBootPayload {
        pages,
        copied_bytes,
    })
}
