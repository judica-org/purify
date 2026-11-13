//! One-shot qualified construction-parent prover.

use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use purify_construction_parent::prover::{
    prove_qualified_construction_parent, ConstructionParentWitness,
    ConstructionParentWitnessBindingError, ConstructionParentWitnessDecodeError,
    QualifiedConstructionParentProvingError,
};
use thiserror::Error;

#[derive(Debug, Error)]
enum CommandError {
    #[error(
        "usage: {program} <prover-artifact> <verifier-artifact> \
         <input.wit3> <output.proof>"
    )]
    Usage { program: String },
    #[error("cannot inspect construction-parent proof output {path}: {source}")]
    InspectOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("construction-parent proof output already exists: {path}")]
    OutputExists { path: PathBuf },
    #[error("cannot read construction-parent witness {path}: {source}")]
    ReadWitness {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Decode(#[from] ConstructionParentWitnessDecodeError),
    #[error(transparent)]
    Bind(#[from] ConstructionParentWitnessBindingError),
    #[error(transparent)]
    Prove(#[from] QualifiedConstructionParentProvingError),
    #[error("cannot create construction-parent proof output {path}: {source}")]
    CreateOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot write construction-parent proof output {path}: {source}")]
    WriteOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot sync construction-parent proof output {path}: {source}")]
    SyncOutput {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

struct Arguments {
    prover_artifact: PathBuf,
    verifier_artifact: PathBuf,
    witness: PathBuf,
    output: PathBuf,
}

fn parse_arguments_from(
    values: impl IntoIterator<Item = OsString>,
) -> Result<Arguments, CommandError> {
    let mut values = values.into_iter();
    let program = values
        .next()
        .unwrap_or_else(|| OsString::from("purify-construction-parent-prover"));
    let usage = || CommandError::Usage {
        program: program.to_string_lossy().into_owned(),
    };
    let prover_artifact = values.next().ok_or_else(&usage)?;
    let verifier_artifact = values.next().ok_or_else(&usage)?;
    let witness = values.next().ok_or_else(&usage)?;
    let output = values.next().ok_or_else(&usage)?;
    if values.next().is_some() {
        return Err(usage());
    }
    Ok(Arguments {
        prover_artifact: prover_artifact.into(),
        verifier_artifact: verifier_artifact.into(),
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

fn run(arguments: Arguments) -> Result<(), CommandError> {
    require_absent(&arguments.output)?;

    let witness_bytes =
        fs::read(&arguments.witness).map_err(|source| CommandError::ReadWitness {
            path: arguments.witness.clone(),
            source,
        })?;
    let witness = ConstructionParentWitness::decode(&witness_bytes)?.bind()?;

    let proof = prove_qualified_construction_parent(
        witness,
        &arguments.prover_artifact,
        &arguments.verifier_artifact,
    )?;

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&arguments.output)
        .map_err(|source| CommandError::CreateOutput {
            path: arguments.output.clone(),
            source,
        })?;
    output
        .write_all(&proof)
        .map_err(|source| CommandError::WriteOutput {
            path: arguments.output.clone(),
            source,
        })?;
    output
        .sync_all()
        .map_err(|source| CommandError::SyncOutput {
            path: arguments.output,
            source,
        })?;
    Ok(())
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
    use std::process;

    use super::*;

    fn test_directory(label: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "purify-construction-parent-prover-{}-{label}",
            process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path).expect("remove stale prover CLI test directory");
        }
        fs::create_dir(&path).expect("create prover CLI test directory");
        path
    }

    fn nonexistent_inputs(directory: &Path) -> Arguments {
        Arguments {
            prover_artifact: directory.join("missing.pk1"),
            verifier_artifact: directory.join("missing.vk2"),
            witness: directory.join("missing.wit3"),
            output: directory.join("proof.out"),
        }
    }

    #[test]
    fn arguments_require_exactly_four_paths() {
        let valid = ["prover", "pk1", "vk2", "input", "output"]
            .into_iter()
            .map(OsString::from);
        let parsed = parse_arguments_from(valid).expect("parse exact CLI shape");
        assert_eq!(parsed.output, PathBuf::from("output"));

        let missing = ["prover", "pk1", "vk2", "input"]
            .into_iter()
            .map(OsString::from);
        assert!(matches!(
            parse_arguments_from(missing),
            Err(CommandError::Usage { .. })
        ));
        let extra = ["prover", "pk1", "vk2", "input", "output", "extra"]
            .into_iter()
            .map(OsString::from);
        assert!(matches!(
            parse_arguments_from(extra),
            Err(CommandError::Usage { .. })
        ));
    }

    #[test]
    fn existing_output_is_untouched_before_any_input_work() {
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
    fn malformed_witness_rejects_before_artifact_loading() {
        let directory = test_directory("malformed-witness");
        let arguments = nonexistent_inputs(&directory);
        fs::write(&arguments.witness, []).expect("write malformed witness");

        assert!(matches!(run(arguments), Err(CommandError::Decode(_))));
        assert!(!directory.join("proof.out").exists());
        fs::remove_dir_all(directory).expect("remove prover CLI test directory");
    }
}
