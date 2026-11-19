//! Positional file I/O on every platform (Unix `pread`/`pwrite`, Windows
//! `seek_read`/`seek_write`). Safe to call concurrently on one `File`.
use std::fs::File;
use std::io;

pub fn read_exact_at(f: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::read_at(f, buf, offset)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_read(f, buf, offset)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

pub fn write_all_at(f: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        #[cfg(unix)]
        let n = std::os::unix::fs::FileExt::write_at(f, buf, offset)?;
        #[cfg(windows)]
        let n = std::os::windows::fs::FileExt::seek_write(f, buf, offset)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write whole buffer"));
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let d = tempfile_dir();
        let p = d.join("x");
        let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&p).unwrap();
        f.set_len(10).unwrap();
        super::write_all_at(&f, b"abc", 5).unwrap();
        let mut b = [0u8; 3];
        super::read_exact_at(&f, &mut b, 5).unwrap();
        assert_eq!(&b, b"abc");
        assert!(super::read_exact_at(&f, &mut [0u8; 8], 5).is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fsx-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}
