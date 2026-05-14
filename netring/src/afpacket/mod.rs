//! AF_PACKET backend implementation.

pub(crate) mod ffi;

pub(crate) mod fanout;
pub(crate) mod filter;
pub(crate) mod ring;
pub mod rx;
pub(crate) mod socket;
pub mod tx;

use crate::error::Error;

/// Validate frame_size constraints shared by RX and TX builders.
pub(crate) fn validate_frame_size(frame_size: usize) -> Result<(), Error> {
    if !frame_size.is_multiple_of(ffi::TPACKET_ALIGNMENT) {
        return Err(Error::Config(format!(
            "frame_size {} is not a multiple of TPACKET_ALIGNMENT ({})",
            frame_size,
            ffi::TPACKET_ALIGNMENT
        )));
    }
    if frame_size < ffi::TPACKET3_HDRLEN {
        return Err(Error::Config(format!(
            "frame_size {} is less than TPACKET3_HDRLEN ({})",
            frame_size,
            ffi::TPACKET3_HDRLEN
        )));
    }
    Ok(())
}
