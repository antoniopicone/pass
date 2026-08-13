use std::path::Path;

/// Decode the first QR code found in an image file into its raw text
/// content (e.g. an `otpauth://totp/...` URI).
pub fn decode_qr_image(path: &Path) -> Result<String, String> {
    let img = image::open(path)
        .map_err(|e| format!("Failed to open image: {e}"))?
        .to_luma8();

    let mut prepared = rqrr::PreparedImage::prepare(img);
    let grids = prepared.detect_grids();
    let grid = grids.first().ok_or_else(|| "No QR code found in image".to_string())?;

    let (_meta, content) = grid.decode().map_err(|e| format!("Failed to decode QR code: {e}"))?;
    Ok(content)
}
