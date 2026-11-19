//! Private, immutable input snapshots for production artifact loading.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const SNAPSHOT_ID_BYTES: usize = 16;

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
    create_unlinked_private_file_in(&directory, random_snapshot_id)
}

fn create_unlinked_private_file_in<F>(directory: &Path, mut next_id: F) -> io::Result<File>
where
    F: FnMut() -> io::Result<[u8; SNAPSHOT_ID_BYTES]>,
{
    loop {
        let path = snapshot_path(directory, next_id()?);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                fs::remove_file(&path)?;
                if file.metadata()?.nlink() != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "private artifact snapshot remains linked",
                    ));
                }
                return Ok(file);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
}

fn random_snapshot_id() -> io::Result<[u8; SNAPSHOT_ID_BYTES]> {
    let mut id = [0u8; SNAPSHOT_ID_BYTES];
    getrandom::getrandom(&mut id).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(id)
}

fn snapshot_path(directory: &Path, id: [u8; SNAPSHOT_ID_BYTES]) -> std::path::PathBuf {
    directory.join(format!(
        ".purify-artifact-snapshot-{:032x}",
        u128::from_be_bytes(id)
    ))
}

#[cfg(test)]
mod tests {
    use std::fs::DirBuilder;
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::{Arc, Barrier};
    use std::thread;

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

    #[test]
    fn snapshot_creation_retries_an_existing_random_name() {
        let directory = TestDirectory::new();
        let collision_id = [0x11; SNAPSHOT_ID_BYTES];
        let fresh_id = [0x22; SNAPSHOT_ID_BYTES];
        let collision_path = snapshot_path(directory.path(), collision_id);
        File::create(&collision_path).expect("create colliding file");
        let mut ids = [collision_id, fresh_id].into_iter();

        let file = create_unlinked_private_file_in(directory.path(), || {
            Ok(ids.next().expect("snapshot requested an unexpected ID"))
        })
        .expect("retry colliding snapshot name");

        assert_eq!(file.metadata().expect("snapshot metadata").nlink(), 0);
        assert!(collision_path.exists());
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("read test directory")
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_snapshot_files_are_isolated_and_unlinked() {
        const THREADS: usize = 16;

        let directory = TestDirectory::new();
        let barrier = Arc::new(Barrier::new(THREADS));
        thread::scope(|scope| {
            let mut joins = Vec::with_capacity(THREADS);
            for marker in 0..THREADS {
                let directory = directory.path().to_owned();
                let barrier = Arc::clone(&barrier);
                joins.push(scope.spawn(move || {
                    barrier.wait();
                    let mut file = create_unlinked_private_file_in(&directory, random_snapshot_id)
                        .expect("create concurrent snapshot");
                    let marker = u8::try_from(marker).expect("test marker fits u8");
                    file.write_all(&[marker]).expect("write snapshot marker");
                    file.seek(SeekFrom::Start(0)).expect("rewind snapshot");
                    let mut actual = [0u8; 1];
                    file.read_exact(&mut actual).expect("read snapshot marker");
                    assert_eq!(actual, [marker]);
                    assert_eq!(file.metadata().expect("snapshot metadata").nlink(), 0);
                }));
            }
            for join in joins {
                join.join().expect("snapshot thread");
            }
        });
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("read test directory")
                .count(),
            0
        );
    }

    fn unlinked_source(contents: &[u8]) -> (File, File) {
        let directory = TestDirectory::new();
        let path = directory.path().join("source");
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("create source");
        writer.write_all(contents).expect("write source");
        let reader = File::open(&path).expect("open source read-only");
        fs::remove_file(path).expect("unlink source");
        (reader, writer)
    }

    struct TestDirectory {
        path: std::path::PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let path = snapshot_path(
                    &env::temp_dir(),
                    random_snapshot_id().expect("generate test directory ID"),
                );
                match DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create test directory: {error}"),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).expect("remove test directory");
        }
    }
}
