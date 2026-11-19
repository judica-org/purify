//! One-shot qualified certificate-parent prover.
//!
//! The emitted bytes remain unaccepted until the C++ certificate verifier
//! authenticates the recursive proof and completes native BP++ `decide()`.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use purify_construction_parent::certificate_parent_prover::{
    prove_qualified_certificate_parent, CertificateParentPublicFrame,
    CertificateParentPublicFrameDecodeError, CertificateParentWitness,
    CertificateParentWitnessBindingError, CertificateParentWitnessDecodeError,
    QualifiedCertificateParentProvingError, CERTIFICATE_PARENT_PROOF_SIZE,
};
use thiserror::Error;

/// Operational allocation bound for one local proving request.
///
/// 256 MiB leaves ample room for witnesses derived from the current 4 MB
/// compact-receipt descriptor envelope. This is not a consensus or relation
/// limit; it protects this one-shot producer from unbounded local input.
const MAX_CERTIFICATE_PARENT_WITNESS_BYTES: usize = 256 * 1024 * 1024;
const TEMPORARY_NAME_ATTEMPTS: usize = 16;

#[derive(Debug, Error)]
enum CommandError {
    #[error(
        "usage: {program} <prover-artifact> <verifier-artifact> \
         <public-frame.cpi1> <input.certjwit3> <output.proof>"
    )]
    Usage { program: String },
    #[error("cannot inspect certificate-parent proof output {path}: {source}")]
    InspectOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("certificate-parent proof output already exists: {path}")]
    OutputExists { path: PathBuf },
    #[error("certificate-parent proof output has no file name: {path}")]
    InvalidOutputPath { path: PathBuf },
    #[error("cannot open certificate-parent public frame {path}: {source}")]
    OpenPublicFrame {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot read certificate-parent public frame {path}: {source}")]
    ReadPublicFrame {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    DecodePublicFrame(#[from] CertificateParentPublicFrameDecodeError),
    #[error("cannot open certificate-parent witness {path}: {source}")]
    OpenWitness {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot read certificate-parent witness {path}: {source}")]
    ReadWitness {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "certificate-parent witness {path} exceeds the {maximum}-byte \
         local allocation limit"
    )]
    WitnessTooLarge { path: PathBuf, maximum: usize },
    #[error(transparent)]
    DecodeWitness(#[from] CertificateParentWitnessDecodeError),
    #[error(transparent)]
    BindWitness(#[from] CertificateParentWitnessBindingError),
    #[error(transparent)]
    Prove(#[from] QualifiedCertificateParentProvingError),
    #[error(
        "qualified certificate-parent proof length mismatch: expected \
         {expected}, actual {actual}"
    )]
    ProofLength { expected: usize, actual: usize },
    #[error("cannot obtain randomness for a temporary proof name: {detail}")]
    TemporaryNameRandomness { detail: String },
    #[error(
        "cannot create a temporary certificate-parent proof beside {path}: \
         {source}"
    )]
    CreateTemporary {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot write temporary certificate-parent proof {path}: {source}")]
    WriteTemporary {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot sync temporary certificate-parent proof {path}: {source}")]
    SyncTemporary {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot publish certificate-parent proof {path}: {source}")]
    PublishOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot open certificate-parent output directory {path}: {source}")]
    OpenOutputDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot sync certificate-parent output directory {path}: {source}")]
    SyncOutputDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot remove temporary certificate-parent proof {path}: {source}")]
    RemoveTemporary {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

struct Arguments {
    prover_artifact: PathBuf,
    verifier_artifact: PathBuf,
    public_frame: PathBuf,
    witness: PathBuf,
    output: PathBuf,
}

fn parse_arguments_from(
    values: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, CommandError> {
    let mut values = values.into_iter();
    let program = values
        .next()
        .unwrap_or_else(|| OsString::from("purify-certificate-parent-prover"));
    let usage = || CommandError::Usage {
        program: program.to_string_lossy().into_owned(),
    };
    let prover_artifact = values.next().ok_or_else(&usage)?;
    let verifier_artifact = values.next().ok_or_else(&usage)?;
    let public_frame = values.next().ok_or_else(&usage)?;
    let witness = values.next().ok_or_else(&usage)?;
    let output = values.next().ok_or_else(&usage)?;
    if values.next().is_some() {
        return Err(usage());
    }
    Ok(Arguments {
        prover_artifact: prover_artifact.into(),
        verifier_artifact: verifier_artifact.into(),
        public_frame: public_frame.into(),
        witness: witness.into(),
        output: output.into(),
    })
}

fn parse_arguments() -> Result<Arguments, CommandError> {
    parse_arguments_from(env::args_os())
}

fn require_absent(path: &Path) -> Result<(), CommandError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(CommandError::OutputExists {
            path: path.to_owned(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(CommandError::InspectOutput {
            path: path.to_owned(),
            source,
        }),
    }
}

fn read_public_frame(path: &Path) -> Result<CertificateParentPublicFrame, CommandError> {
    let input = File::open(path).map_err(|source| CommandError::OpenPublicFrame {
        path: path.to_owned(),
        source,
    })?;
    let mut bytes = Vec::with_capacity(CertificateParentPublicFrame::SERIALIZED_SIZE + 1);
    input
        .take(CertificateParentPublicFrame::SERIALIZED_SIZE as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CommandError::ReadPublicFrame {
            path: path.to_owned(),
            source,
        })?;
    Ok(CertificateParentPublicFrame::decode(&bytes)?)
}

fn read_witness(path: &Path, maximum: usize) -> Result<Vec<u8>, CommandError> {
    let input = File::open(path).map_err(|source| CommandError::OpenWitness {
        path: path.to_owned(),
        source,
    })?;
    let initial_capacity = input
        .metadata()
        .map_err(|source| CommandError::ReadWitness {
            path: path.to_owned(),
            source,
        })?
        .len()
        .min(maximum as u64 + 1) as usize;
    let mut witness = Vec::with_capacity(initial_capacity);
    input
        .take(maximum as u64 + 1)
        .read_to_end(&mut witness)
        .map_err(|source| CommandError::ReadWitness {
            path: path.to_owned(),
            source,
        })?;
    if witness.len() > maximum {
        return Err(CommandError::WitnessTooLarge {
            path: path.to_owned(),
            maximum,
        });
    }
    Ok(witness)
}

struct TemporaryProof {
    path: PathBuf,
    remove_on_drop: bool,
}

impl TemporaryProof {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            remove_on_drop: true,
        }
    }

    fn remove(mut self) -> Result<(), CommandError> {
        fs::remove_file(&self.path).map_err(|source| CommandError::RemoveTemporary {
            path: self.path.clone(),
            source,
        })?;
        self.remove_on_drop = false;
        Ok(())
    }
}

impl Drop for TemporaryProof {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn output_directory(path: &Path) -> Result<(&Path, &OsStr), CommandError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| CommandError::InvalidOutputPath {
            path: path.to_owned(),
        })?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok((parent, file_name))
}

fn create_temporary_output(output: &Path) -> Result<(File, TemporaryProof), CommandError> {
    let (directory, file_name) = output_directory(output)?;
    for _ in 0..TEMPORARY_NAME_ATTEMPTS {
        let mut random = [0u8; 16];
        getrandom::getrandom(&mut random).map_err(|error| {
            CommandError::TemporaryNameRandomness {
                detail: error.to_string(),
            }
        })?;
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(format!(".{suffix}.partial"));
        let temporary_path = directory.join(temporary_name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => {
                return Ok((file, TemporaryProof::new(temporary_path)));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(CommandError::CreateTemporary {
                    path: output.to_owned(),
                    source,
                });
            }
        }
    }
    Err(CommandError::CreateTemporary {
        path: output.to_owned(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary proof name collision limit reached",
        ),
    })
}

fn sync_directory(path: &Path) -> Result<(), CommandError> {
    let directory = File::open(path).map_err(|source| CommandError::OpenOutputDirectory {
        path: path.to_owned(),
        source,
    })?;
    directory
        .sync_all()
        .map_err(|source| CommandError::SyncOutputDirectory {
            path: path.to_owned(),
            source,
        })
}

fn publish_proof(output: &Path, proof: &[u8]) -> Result<(), CommandError> {
    if proof.len() != CERTIFICATE_PARENT_PROOF_SIZE {
        return Err(CommandError::ProofLength {
            expected: CERTIFICATE_PARENT_PROOF_SIZE,
            actual: proof.len(),
        });
    }
    let (directory, _) = output_directory(output)?;
    let (mut file, temporary) = create_temporary_output(output)?;
    file.write_all(proof)
        .map_err(|source| CommandError::WriteTemporary {
            path: temporary.path.clone(),
            source,
        })?;
    file.sync_all()
        .map_err(|source| CommandError::SyncTemporary {
            path: temporary.path.clone(),
            source,
        })?;
    drop(file);

    match fs::hard_link(&temporary.path, output) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
            return Err(CommandError::OutputExists {
                path: output.to_owned(),
            });
        }
        Err(source) => {
            return Err(CommandError::PublishOutput {
                path: output.to_owned(),
                source,
            });
        }
    }
    sync_directory(directory)?;
    temporary.remove()?;
    sync_directory(directory)
}

fn run_with_witness_limit(
    arguments: Arguments,
    maximum_witness_bytes: usize,
) -> Result<(), CommandError> {
    require_absent(&arguments.output)?;

    let public_frame = read_public_frame(&arguments.public_frame)?;
    let witness_bytes = read_witness(&arguments.witness, maximum_witness_bytes)?;
    let witness = CertificateParentWitness::decode(&witness_bytes)?;
    drop(witness_bytes);
    let checked = witness.bind(public_frame)?;

    let proof = prove_qualified_certificate_parent(
        checked,
        &arguments.prover_artifact,
        &arguments.verifier_artifact,
    )?;
    publish_proof(&arguments.output, &proof)
}

fn run(arguments: Arguments) -> Result<(), CommandError> {
    run_with_witness_limit(arguments, MAX_CERTIFICATE_PARENT_WITNESS_BYTES)
}

fn main() -> ExitCode {
    match parse_arguments().and_then(run) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const PINNED_WITNESS: &[u8] =
        include_bytes!("../../tests/vectors/certificate_joined_witness_v3.bin");
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn test_directory(label: &str) -> PathBuf {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "purify-certificate-parent-prover-{}-{sequence}-{label}",
            std::process::id(),
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove stale prover CLI test directory");
        }
        fs::create_dir(&path).expect("create prover CLI test directory");
        path
    }

    fn public_frame_bytes() -> [u8; CertificateParentPublicFrame::SERIALIZED_SIZE] {
        let mut encoded = [0u8; CertificateParentPublicFrame::SERIALIZED_SIZE];
        encoded[..16].copy_from_slice(b"Purify/CertPub1\0");
        encoded[16..48].fill(1);
        encoded[48..56].copy_from_slice(&1u64.to_be_bytes());
        encoded[56..64].copy_from_slice(&1u64.to_be_bytes());
        encoded[64..96].fill(1);
        encoded
    }

    fn nonexistent_inputs(directory: &Path) -> Arguments {
        Arguments {
            prover_artifact: directory.join("missing.pk1"),
            verifier_artifact: directory.join("missing.vk2"),
            public_frame: directory.join("public.cpi1"),
            witness: directory.join("input.certjwit3"),
            output: directory.join("proof.out"),
        }
    }

    #[test]
    fn arguments_require_exactly_five_paths() {
        let valid = ["prover", "pk1", "vk2", "public", "witness", "output"]
            .into_iter()
            .map(OsString::from);
        let parsed = parse_arguments_from(valid).expect("parse exact CLI shape");
        assert_eq!(parsed.output, PathBuf::from("output"));

        let missing = ["prover", "pk1", "vk2", "public", "witness"]
            .into_iter()
            .map(OsString::from);
        assert!(matches!(
            parse_arguments_from(missing),
            Err(CommandError::Usage { .. })
        ));
        let extra = [
            "prover", "pk1", "vk2", "public", "witness", "output", "extra",
        ]
        .into_iter()
        .map(OsString::from);
        assert!(matches!(
            parse_arguments_from(extra),
            Err(CommandError::Usage { .. })
        ));
    }

    #[test]
    fn public_frame_reader_requires_exact_canonical_bytes() {
        let directory = test_directory("public-frame");
        let path = directory.join("public.cpi1");
        fs::write(&path, public_frame_bytes()).expect("write public frame");
        read_public_frame(&path).expect("read exact public frame");

        let mut trailing = public_frame_bytes().to_vec();
        trailing.push(0);
        fs::write(&path, trailing).expect("write trailing public frame");
        assert!(matches!(
            read_public_frame(&path),
            Err(CommandError::DecodePublicFrame(_))
        ));
        fs::remove_file(path).expect("remove public frame");
        fs::remove_dir(directory).expect("remove prover CLI test directory");
    }

    #[test]
    fn malformed_witness_rejects_before_artifact_loading() {
        let directory = test_directory("malformed-witness");
        let arguments = nonexistent_inputs(&directory);
        fs::write(&arguments.public_frame, public_frame_bytes()).expect("write public frame");
        fs::write(&arguments.witness, []).expect("write malformed witness");

        assert!(matches!(
            run(arguments),
            Err(CommandError::DecodeWitness(_))
        ));
        assert!(!directory.join("proof.out").exists());
        fs::remove_dir_all(directory).expect("remove prover CLI test directory");
    }

    #[test]
    fn external_frame_mismatch_rejects_before_artifact_loading() {
        let directory = test_directory("mismatched-public-frame");
        let arguments = nonexistent_inputs(&directory);
        fs::write(&arguments.public_frame, public_frame_bytes()).expect("write public frame");
        fs::write(&arguments.witness, PINNED_WITNESS).expect("write pinned witness");

        assert!(matches!(run(arguments), Err(CommandError::BindWitness(_))));
        assert!(!directory.join("proof.out").exists());
        fs::remove_dir_all(directory).expect("remove prover CLI test directory");
    }

    #[test]
    fn oversized_witness_rejects_before_artifact_loading() {
        let directory = test_directory("oversized-witness");
        let arguments = nonexistent_inputs(&directory);
        fs::write(&arguments.public_frame, public_frame_bytes()).expect("write public frame");
        fs::write(&arguments.witness, [0u8; 17]).expect("write oversized witness");

        assert!(matches!(
            run_with_witness_limit(arguments, 16),
            Err(CommandError::WitnessTooLarge { maximum: 16, .. })
        ));
        assert!(!directory.join("proof.out").exists());
        fs::remove_dir_all(directory).expect("remove prover CLI test directory");
    }

    #[test]
    fn existing_output_is_untouched_before_input_work() {
        let directory = test_directory("existing-output");
        let arguments = nonexistent_inputs(&directory);
        fs::write(&arguments.output, b"keep this output").expect("write existing output");

        assert!(matches!(
            run(arguments),
            Err(CommandError::OutputExists { .. })
        ));
        assert_eq!(
            fs::read(directory.join("proof.out")).expect("reread existing output"),
            b"keep this output"
        );
        fs::remove_dir_all(directory).expect("remove prover CLI test directory");
    }

    #[test]
    fn proof_publication_is_atomic_no_replace_and_cleans_temporary() {
        let directory = test_directory("publish");
        let output = directory.join("proof.out");
        let first = vec![0x11; CERTIFICATE_PARENT_PROOF_SIZE];
        publish_proof(&output, &first).expect("publish first proof");
        assert_eq!(fs::read(&output).expect("read first proof"), first);
        assert_eq!(
            fs::read_dir(&directory)
                .expect("read output directory")
                .count(),
            1
        );

        let second = vec![0x22; CERTIFICATE_PARENT_PROOF_SIZE];
        assert!(matches!(
            publish_proof(&output, &second),
            Err(CommandError::OutputExists { .. })
        ));
        assert_eq!(fs::read(&output).expect("reread first proof"), first);
        assert_eq!(
            fs::read_dir(&directory)
                .expect("reread output directory")
                .count(),
            1
        );

        fs::remove_file(output).expect("remove proof output");
        fs::remove_dir(directory).expect("remove prover CLI test directory");
    }

    #[test]
    fn wrong_proof_length_creates_no_output_or_temporary() {
        let directory = test_directory("wrong-proof-length");
        let output = directory.join("proof.out");
        assert!(matches!(
            publish_proof(&output, &vec![0; CERTIFICATE_PARENT_PROOF_SIZE - 1]),
            Err(CommandError::ProofLength { .. })
        ));
        assert_eq!(
            fs::read_dir(&directory)
                .expect("read empty output directory")
                .count(),
            0
        );
        fs::remove_dir(directory).expect("remove prover CLI test directory");
    }
}
