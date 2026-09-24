//! Checked current-mode GOP presentation for a separately owned guest framebuffer.
extern crate alloc;

use alloc::vec::Vec;
use uefi::boot::{self, ScopedProtocol};
use uefi::proto::console::gop::{BltOp, BltPixel, BltRegion, GraphicsOutput};
use uefi::Status;

pub const MAX_DIMENSION: u32 = 8192;

/// Contiguous little-endian XRGB8888 guest geometry, independent of GOP stride.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    width: u32,
    height: u32,
    row_bytes: u32,
    byte_len: usize,
}

impl Geometry {
    pub fn new(width: u32, height: u32) -> Result<Self, Status> {
        if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(Status::UNSUPPORTED);
        }
        let row_bytes = width.checked_mul(4).ok_or(Status::BAD_BUFFER_SIZE)?;
        let byte_len = usize::try_from(row_bytes)
            .ok()
            .and_then(|row| row.checked_mul(height as usize))
            .ok_or(Status::BAD_BUFFER_SIZE)?;
        Ok(Self {
            width,
            height,
            row_bytes,
            byte_len,
        })
    }

    pub const fn width(self) -> u32 {
        self.width
    }
    pub const fn height(self) -> u32 {
        self.height
    }
    pub const fn row_bytes(self) -> u32 {
        self.row_bytes
    }
    pub const fn byte_len(self) -> usize {
        self.byte_len
    }

    fn dimensions(self) -> (usize, usize) {
        (self.width as usize, self.height as usize)
    }
}

fn blt_pixels(geometry: Geometry, bytes: &[u8]) -> Result<Vec<BltPixel>, Status> {
    if bytes.len() != geometry.byte_len() {
        return Err(Status::BAD_BUFFER_SIZE);
    }
    let mut pixels = Vec::new();
    pixels
        .try_reserve_exact(bytes.len() / 4)
        .map_err(|_| Status::OUT_OF_RESOURCES)?;
    for pixel in bytes.chunks_exact(4) {
        pixels.push(BltPixel::new(pixel[2], pixel[1], pixel[0]));
    }
    Ok(pixels)
}

/// Owns the protocol until dropped; all methods require active boot services.
pub struct CurrentGop {
    protocol: ScopedProtocol<GraphicsOutput>,
    geometry: Geometry,
}

impl CurrentGop {
    /// Acquires an available GOP and reads its current mode without changing it.
    pub fn open() -> Result<Self, Status> {
        let handle =
            boot::get_handle_for_protocol::<GraphicsOutput>().map_err(|error| error.status())?;
        let protocol = boot::open_protocol_exclusive::<GraphicsOutput>(handle)
            .map_err(|error| error.status())?;
        let (width, height) = protocol.current_mode_info().resolution();
        let geometry = Geometry::new(
            u32::try_from(width).map_err(|_| Status::UNSUPPORTED)?,
            u32::try_from(height).map_err(|_| Status::UNSUPPORTED)?,
        )?;
        Ok(Self { protocol, geometry })
    }

    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    fn check_current_geometry(&self) -> Result<(), Status> {
        if self.protocol.current_mode_info().resolution() != self.geometry.dimensions() {
            return Err(Status::MEDIA_CHANGED);
        }
        Ok(())
    }

    /// Presents an exact BGRX frame. Firmware failures propagate unchanged.
    pub fn present(&mut self, bytes: &[u8]) -> Result<(), Status> {
        self.check_current_geometry()?;
        let pixels = blt_pixels(self.geometry, bytes)?;
        self.protocol
            .blt(BltOp::BufferToVideo {
                buffer: &pixels,
                src: BltRegion::Full,
                dest: (0, 0),
                dims: self.geometry.dimensions(),
            })
            .map_err(|error| error.status())
    }

    /// Reads actual GOP pixels, normalized to BGRX with zero unused bytes.
    pub fn readback(&mut self) -> Result<Vec<u8>, Status> {
        self.check_current_geometry()?;
        let count = self.geometry.byte_len() / 4;
        let mut pixels = Vec::new();
        pixels
            .try_reserve_exact(count)
            .map_err(|_| Status::OUT_OF_RESOURCES)?;
        pixels.resize(count, BltPixel::new(0, 0, 0));
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.geometry.byte_len())
            .map_err(|_| Status::OUT_OF_RESOURCES)?;
        self.protocol
            .blt(BltOp::VideoToBltBuffer {
                buffer: &mut pixels,
                src: (0, 0),
                dest: BltRegion::Full,
                dims: self.geometry.dimensions(),
            })
            .map_err(|error| error.status())?;
        for pixel in pixels {
            bytes.extend_from_slice(&[pixel.blue, pixel.green, pixel.red, 0]);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_out_of_bounds_firmware_dimensions() {
        for (width, height) in [(0, 1), (1, 0), (8193, 1), (1, 8193), (u32::MAX, u32::MAX)] {
            assert_eq!(Geometry::new(width, height), Err(Status::UNSUPPORTED));
        }
    }

    #[test]
    fn contiguous_guest_stride_and_maximum_are_exact() {
        let odd = Geometry::new(1365, 768).unwrap();
        assert_eq!(odd.row_bytes(), 5460);
        assert_eq!(odd.byte_len(), 4_193_280);
        let maximum = Geometry::new(8192, 8192).unwrap();
        assert_eq!(maximum.row_bytes(), 32768);
        assert_eq!(maximum.byte_len(), 256 * 1024 * 1024);
    }

    #[test]
    fn rejects_short_and_trailing_pixel_buffers() {
        let geometry = Geometry::new(2, 1).unwrap();
        for length in [0, 4, 7, 9, 12] {
            assert_eq!(
                blt_pixels(geometry, &alloc::vec![0; length]).unwrap_err(),
                Status::BAD_BUFFER_SIZE
            );
        }
    }

    #[test]
    fn asymmetric_channels_and_unused_byte_preserve_the_input() {
        let input = [0x12, 0x34, 0x56, 0xff, 0x9a, 0xbc, 0xde, 0x7f];
        let before = input;
        let pixels = blt_pixels(Geometry::new(2, 1).unwrap(), &input).unwrap();
        assert_eq!(
            (pixels[0].red, pixels[0].green, pixels[0].blue),
            (0x56, 0x34, 0x12)
        );
        assert_eq!(
            (pixels[1].red, pixels[1].green, pixels[1].blue),
            (0xde, 0xbc, 0x9a)
        );
        assert_eq!(input, before);
    }
}
