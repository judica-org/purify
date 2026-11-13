//! Private, immutable input snapshots for production artifact loading.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

const CREATE_ATTEMPTS: u64 = 1_024;
static NEXT_SNAPSHOT_ID: AtomicU64 = AtomicU64::new(0);

/// One exact-length file snapshot with no directory entry.
pub(crate) struct PrivateArtifactSnapshot {
    file: File,
}

impl PrivateArtifactSnapshot {
    /// Copy exactly `expected_length` bytes and reject any trailing byte.
    ///
    /// The private destination is unlinked before the copy begins. Once this
    /// returns, later changes to `source` cannot affect artifact parsing.
    pub(crate) fn copy_from<R>(source: &mut R, expected_length: u64) -> io::Result<Self>
    where
        R: Read,
    {
        let copy_limit = expected_length
            .checked_add(1)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut file = create_unlinked_private_file()?;
        let copied = io::copy(&mut source.take(copy_limit), &mut file)?;
        if copied < expected_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "artifact source is shorter than its compiled length",
            ));
        }
        if copied > expected_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "artifact source has bytes after its compiled length",
            ));
        }
        file.seek(SeekFrom::Start(0))?;
        Ok(Self { file })
    }

    pub(crate) fn reader(&mut self) -> &mut File {
        &mut self.file
    }
}

fn create_unlinked_private_file() -> io::Result<File> {
    let directory = env::temp_dir();
    for _ in 0..CREATE_ATTEMPTS {
        let id = NEXT_SNAPSHOT_ID.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".purify-artifact-snapshot-{}-{id}", process::id()));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                fs::remove_file(&path)?;
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique private artifact snapshot",
    ))
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};

    use super::*;

    #[test]
    fn snapshot_isolated_from_later_source_mutation() {
        let original = b"qualified artifact bytes";
        let (mut source, mut source_writer) = unlinked_source(original);
        let mut snapshot = PrivateArtifactSnapshot::copy_from(&mut source, original.len() as u64)
            .expect("copy exact artifact");

        source_writer
            .seek(SeekFrom::Start(0))
            .expect("rewind source writer");
        source_writer
            .write_all(&vec![0; original.len()])
            .expect("mutate source inode");

        let mut copied = Vec::new();
        snapshot
            .reader()
            .read_to_end(&mut copied)
            .expect("read snapshot");
        assert_eq!(copied, original);
    }

    #[test]
    fn snapshot_rejects_short_source() {
        let mut source = Cursor::new(b"short".to_vec());
        let error = PrivateArtifactSnapshot::copy_from(&mut source, 6)
            .err()
            .expect("short source rejects");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn snapshot_rejects_trailing_source() {
        let mut source = Cursor::new(b"trailing".to_vec());
        let error = PrivateArtifactSnapshot::copy_from(&mut source, 7)
            .err()
            .expect("trailing source rejects");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    fn unlinked_source(contents: &[u8]) -> (File, File) {
        let directory = env::temp_dir();
        for _ in 0..CREATE_ATTEMPTS {
            let id = NEXT_SNAPSHOT_ID.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!(
                ".purify-artifact-source-test-{}-{id}",
                process::id()
            ));
            let mut writer = match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create source: {error}"),
            };
            writer.write_all(contents).expect("write source");
            let reader = File::open(&path).expect("open source read-only");
            fs::remove_file(path).expect("unlink source");
            return (reader, writer);
        }
        panic!("could not create unique test source");
    }
}
