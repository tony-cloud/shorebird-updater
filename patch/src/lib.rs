use bidiff::DiffParams;
use std::io::{BufWriter, Seek, Write};

use comde::com::Compressor;
use comde::zstd::ZstdCompressor;

pub fn make_patch<WS>(older: Vec<u8>, newer: Vec<u8>, patch: &mut WS)
where
    WS: Write + Seek,
{
    let (mut patch_r, mut patch_w) = pipe::pipe();
    let diff_params = DiffParams::new(1, None).unwrap();
    let diff_thread = std::thread::spawn(move || {
        if older.is_empty() {
            // The suffix-array diff algorithm cannot search an empty base.
            // Encode one literal-copy control instead: it never reads base
            // bytes, so the replacement also applies over a nonempty app base.
            let mut writer = bidiff::enc::Writer::new(&mut patch_w)?;
            writer.write(&bidiff::Control {
                add: &[],
                copy: &newer,
                seek: 0,
            })?;
            writer.flush()
        } else {
            bidiff::simple_diff_with_params(&older[..], &newer[..], &mut patch_w, &diff_params)
        }
    });

    let compressor = ZstdCompressor::new();

    let mut compatch_w = BufWriter::new(patch);
    compressor
        .compress(&mut compatch_w, &mut patch_r)
        .expect("compress patch");
    compatch_w.flush().expect("flush patch");
    // A failed producer closes its pipe just like EOF. Propagate its failure
    // rather than returning a valid zstd frame around a truncated patch.
    diff_thread
        .join()
        .expect("diff worker panicked")
        .expect("create diff");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_make_patch() {
        let older = b"hello world".to_vec();
        let newer = b"hello world!".to_vec();
        let mut patch = Cursor::new(Vec::new());
        make_patch(older, newer, &mut patch);
        let patch = patch.into_inner();
        assert_eq!(
            patch,
            vec![
                40, 181, 47, 253, 0, 128, 157, 0, 0, 104, 223, 177, 0, 0, 0, 16, 0, 0, 11, 0, 1,
                33, 0, 1, 0, 27, 64, 2
            ]
        );
    }
}
