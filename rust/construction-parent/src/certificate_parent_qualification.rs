//! Resource-gated qualification for the certificate-parent Nova suite.
//!
//! The public frame below is pinned independently by the native CertJWit3
//! exporter test. Private parent constants never select the manifest supplied
//! to the binder or verifier.

use nova_snark::traits::circuit::StepCircuit;
use sha2::{Digest, Sha256};

use crate::certificate_joined_witness::CertificateLinearJoinedWitness;
use crate::certificate_parent_input::CertificateParentInputs;
use crate::certificate_parent_prover_binding::BoundCertificateParentWitness;
use crate::certificate_profile::CERTIFICATE_RECURRENCE_STATE_ARITY;
use crate::nova_certificate_recurrence::{
    CertificateParentStep, QUALIFIED_CERTIFICATE_PARENT_RELATION_ID,
};
use crate::nova_session::{
    prover_artifact::QUALIFIED_CERTIFICATE_PARENT_PROVER_ARTIFACT,
    verifier_artifact::QUALIFIED_CERTIFICATE_PARENT_VERIFIER_ARTIFACT, NovaSessionStep,
    NovaSessionSuite, SelectedNovaProver, SelectedNovaSessionSuite, SelectedNovaVerifier,
    CERTIFICATE_PARENT_NOVA_APPLICATION, QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE,
};
use crate::nova_types::DirectNovaScalar;

const WITNESS: &[u8] = include_bytes!("../tests/vectors/certificate_joined_witness_v3.bin");
const CONTEXT: [u8; 32] = [
    0x7b, 0xcb, 0x06, 0xb8, 0x53, 0x8c, 0xcc, 0x9c, 0x79, 0xfd, 0x2f, 0x59, 0x5b, 0xbb, 0xee, 0x9f,
    0x08, 0xc0, 0xd8, 0x29, 0xa9, 0x7c, 0xcd, 0x92, 0xfc, 0x31, 0x75, 0xeb, 0x37, 0x90, 0x39, 0xf5,
];
const FINAL_MANIFEST: [u8; 32] = [
    0x45, 0xe8, 0x14, 0x7f, 0x29, 0x3a, 0x6e, 0xdc, 0xf5, 0x0c, 0x17, 0x8d, 0x94, 0xa4, 0x73, 0x1b,
    0x5e, 0x18, 0x78, 0x4c, 0x7b, 0x40, 0x4b, 0xa9, 0xc3, 0x57, 0xb9, 0xdb, 0x22, 0x4c, 0x1f, 0x9c,
];
const RESPONSE_COUNT: u64 = 2;
const STEP_COUNT: u128 = 4;
const PROVER_ARTIFACT_OUT: &str = "PURIFY_CERTIFICATE_PARENT_PROVER_ARTIFACT_OUT";
const VERIFIER_ARTIFACT_OUT: &str = "PURIFY_CERTIFICATE_PARENT_VERIFIER_ARTIFACT_OUT";

type CertificateParentNovaSuite =
    SelectedNovaSessionSuite<CERTIFICATE_RECURRENCE_STATE_ARITY, CertificateParentStep>;

fn public_inputs() -> CertificateParentInputs {
    CertificateParentInputs::new(CONTEXT, RESPONSE_COUNT, STEP_COUNT, FINAL_MANIFEST)
        .expect("fixed certificate parent public inputs")
}

fn witness() -> CertificateLinearJoinedWitness {
    CertificateLinearJoinedWitness::parse(WITNESS).expect("fixed real CertJWit3 witness")
}

fn bound_witness() -> BoundCertificateParentWitness {
    witness()
        .bind(public_inputs())
        .expect("bind real CertJWit3 under its external public frame")
}

fn produce_qualification_proof(
    suite: &CertificateParentNovaSuite,
    initial_state: [DirectNovaScalar; CERTIFICATE_RECURRENCE_STATE_ARITY],
    steps: Vec<CertificateParentStep>,
) -> Vec<u8> {
    let step_count = steps.len();
    let folding_started = std::time::Instant::now();
    let mut session = suite
        .start(initial_state, step_count)
        .expect("start certificate qualification proof");
    for (index, step) in steps.into_iter().enumerate() {
        eprintln!(
            "certificate_parent_qualification: folding step {}/{}",
            index + 1,
            step_count
        );
        session = session
            .add_step(step)
            .expect("fold certificate qualification step");
    }
    eprintln!(
        "certificate_parent_qualification: folding_seconds={:.3}",
        folding_started.elapsed().as_secs_f64(),
    );
    let finish_started = std::time::Instant::now();
    let proof = session
        .finish()
        .expect("compress certificate qualification proof");
    eprintln!(
        "certificate_parent_qualification: finish_compression_seconds={:.3}",
        finish_started.elapsed().as_secs_f64(),
    );
    proof
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn qualification_output_path(environment: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(
        std::env::var_os(environment)
            .unwrap_or_else(|| panic!("set {environment} before qualification")),
    );
    assert!(!path.as_os_str().is_empty(), "{environment} is empty");
    assert!(!path.exists(), "{environment} already exists");
    path
}

fn qualification_file_sha256(path: &std::path::Path) -> [u8; 32] {
    use std::io::Read;

    let mut input = std::fs::File::open(path).expect("open qualification output for hashing");
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .expect("read qualification output for hashing");
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    digest.finalize().into()
}

#[test]
fn qualification_uses_the_native_pinned_public_frame() {
    let witness = witness();
    assert_eq!(witness.frame().certificate_context_digest(), CONTEXT);
    assert_eq!(witness.frame().total_responses(), RESPONSE_COUNT);
    assert_eq!(
        witness
            .responses()
            .iter()
            .map(|response| response.member_proofs().len())
            .sum::<usize>(),
        usize::try_from(STEP_COUNT).expect("fixed step count fits usize")
    );

    let inputs = public_inputs();
    assert_eq!(inputs.step_count(), 4);
    assert_eq!(
        inputs.initial_state(),
        &crate::certificate_recurrence::CertificateRecurrenceStateWitness::genesis(
            CONTEXT,
            RESPONSE_COUNT
        )
        .expect("certificate genesis")
        .state_fields()
        .expect("certificate genesis fields")
    );
}

#[test]
#[ignore = "performs certificate relation binding and transparent Nova setup"]
fn native_certificate_parent_qualification_round_trips() {
    let started = std::time::Instant::now();
    let binding_started = std::time::Instant::now();
    let bound = bound_witness();
    eprintln!(
        "certificate_parent_qualification: binding_seconds={:.3}",
        binding_started.elapsed().as_secs_f64(),
    );
    let trusted_step = bound
        .trusted_setup_step()
        .expect("real certificate witness has a step");
    assert_eq!(trusted_step.arity(), CERTIFICATE_RECURRENCE_STATE_ARITY);
    assert_eq!(
        NovaSessionStep::relation_id(&trusted_step),
        QUALIFIED_CERTIFICATE_PARENT_RELATION_ID
    );

    eprintln!("certificate_parent_qualification: constructing transparent parameters");
    let setup_started = std::time::Instant::now();
    let selected =
        NovaSessionSuite::<CERTIFICATE_RECURRENCE_STATE_ARITY, CertificateParentStep>::setup_exact(
            trusted_step,
            &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE,
        )
        .expect("qualified certificate parent suite");
    let metadata = selected.metadata();
    let versions = CERTIFICATE_PARENT_NOVA_APPLICATION.version_values();
    eprintln!(
        "certificate_parent_qualification: setup_seconds={:.3}\n\
         payload_version={} statement_version={} manifest_version={} \
         native_decision_version={}\nrelation_id={}\n\
         public_parameter_digest={}\nsuite_id={}\nmetadata={metadata:#?}\n\
         generated_suite={:#?}",
        setup_started.elapsed().as_secs_f64(),
        versions.0,
        versions.1,
        versions.2,
        versions.3,
        hex(metadata.relation_id.bytes()),
        hex(&metadata.public_parameter_digest),
        hex(selected.expected().suite_id().bytes()),
        selected.expected(),
    );

    let (initial_state, final_state, steps, pending_root) = bound.into_parts();
    let step_count = steps.len();
    assert_eq!(step_count, 4);
    let proof = produce_qualification_proof(&selected, initial_state, steps);
    assert_eq!(proof.len(), metadata.proof_length);
    let verifier = selected.into_verifier();
    let verification_started = std::time::Instant::now();
    verifier
        .verify_exact(&initial_state, step_count, &final_state, &proof)
        .expect("verify certificate qualification proof");
    eprintln!(
        "certificate_parent_qualification: verification_seconds={:.3}",
        verification_started.elapsed().as_secs_f64(),
    );
    let frame_validation_started = std::time::Instant::now();
    let pending = public_inputs()
        .validate_authenticated_final_state(final_state)
        .expect("revalidate certificate qualification public frame");
    assert_eq!(pending.canonical_root_bytes(), &pending_root);
    eprintln!(
        "certificate_parent_qualification: frame_validation_seconds={:.3}\n\
         proof_bytes={} total_seconds={:.3}",
        frame_validation_started.elapsed().as_secs_f64(),
        proof.len(),
        started.elapsed().as_secs_f64(),
    );
}

#[test]
#[ignore = "performs production setup and writes multi-gigabyte artifacts"]
fn setup_only_certificate_parent_qualification_writes_artifacts() {
    let started = std::time::Instant::now();
    let prover_artifact_path = qualification_output_path(PROVER_ARTIFACT_OUT);
    let verifier_artifact_path = qualification_output_path(VERIFIER_ARTIFACT_OUT);
    assert_ne!(prover_artifact_path, verifier_artifact_path);

    let binding_started = std::time::Instant::now();
    let bound = bound_witness();
    let trusted_step = bound
        .trusted_setup_step()
        .expect("real certificate witness has a step");
    drop(bound);
    let binding_seconds = binding_started.elapsed().as_secs_f64();

    let setup_started = std::time::Instant::now();
    let selected =
        NovaSessionSuite::<CERTIFICATE_RECURRENCE_STATE_ARITY, CertificateParentStep>::setup_exact(
            trusted_step,
            &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE,
        )
        .expect("setup exact qualified certificate parent suite");
    let setup_seconds = setup_started.elapsed().as_secs_f64();
    let (prover, verifier) = selected.into_artifact_parts();

    let mut prover_artifact = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&prover_artifact_path)
        .expect("create new certificate prover artifact");
    let mut verifier_artifact = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&verifier_artifact_path)
        .expect("create new certificate verifier artifact");

    let prover_write_started = std::time::Instant::now();
    let prover_descriptor = prover
        .write_artifact(&mut prover_artifact)
        .expect("write certificate prover artifact");
    assert_eq!(
        prover_descriptor,
        QUALIFIED_CERTIFICATE_PARENT_PROVER_ARTIFACT
    );
    prover_artifact
        .sync_all()
        .expect("sync certificate prover artifact");
    drop(prover_artifact);
    let prover_write_seconds = prover_write_started.elapsed().as_secs_f64();

    let verifier_write_started = std::time::Instant::now();
    let verifier_descriptor = verifier
        .write_artifact(&mut verifier_artifact)
        .expect("write certificate verifier artifact");
    assert_eq!(
        verifier_descriptor,
        QUALIFIED_CERTIFICATE_PARENT_VERIFIER_ARTIFACT
    );
    verifier_artifact
        .sync_all()
        .expect("sync certificate verifier artifact");
    drop(verifier_artifact);
    drop(verifier);
    let verifier_write_seconds = verifier_write_started.elapsed().as_secs_f64();

    let hash_started = std::time::Instant::now();
    let prover_sha256 = qualification_file_sha256(&prover_artifact_path);
    let verifier_sha256 = qualification_file_sha256(&verifier_artifact_path);
    let hash_seconds = hash_started.elapsed().as_secs_f64();

    let prover_reload_started = std::time::Instant::now();
    let mut prover_artifact = std::fs::File::open(&prover_artifact_path)
        .expect("open certificate prover artifact read-only");
    let prover = SelectedNovaProver::<
        CERTIFICATE_RECURRENCE_STATE_ARITY,
        CertificateParentStep,
    >::from_artifact_reader(
        &mut prover_artifact,
        &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE,
        &QUALIFIED_CERTIFICATE_PARENT_PROVER_ARTIFACT,
    )
    .expect("reload certificate prover artifact");
    assert_eq!(prover.expected(), &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE);
    drop(prover_artifact);
    drop(prover);
    let prover_reload_seconds = prover_reload_started.elapsed().as_secs_f64();

    let verifier_reload_started = std::time::Instant::now();
    let mut verifier_artifact = std::fs::File::open(&verifier_artifact_path)
        .expect("open certificate verifier artifact read-only");
    let verifier = SelectedNovaVerifier::<
        CERTIFICATE_RECURRENCE_STATE_ARITY,
        CertificateParentStep,
    >::from_artifact_reader(
        &mut verifier_artifact,
        &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE,
        &QUALIFIED_CERTIFICATE_PARENT_VERIFIER_ARTIFACT,
    )
    .expect("reload certificate verifier artifact");
    assert_eq!(
        verifier.expected(),
        &QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE
    );
    drop(verifier_artifact);
    drop(verifier);
    let verifier_reload_seconds = verifier_reload_started.elapsed().as_secs_f64();
    eprintln!(
        "certificate_parent_artifacts:\n\
         suite_id={}\nprover_artifact={}\nprover_encoded_bytes={}\n\
         prover_decoded_bytes={}\nprover_tagged_digest={}\n\
         prover_sha256={}\nverifier_artifact={}\n\
         verifier_encoded_bytes={}\nverifier_decoded_bytes={}\n\
         verifier_tagged_digest={}\nverifier_sha256={}\n\
         binding_seconds={:.3}\nsetup_seconds={:.3}\n\
         prover_write_seconds={:.3}\nverifier_write_seconds={:.3}\n\
         hash_seconds={:.3}\nprover_reload_seconds={:.3}\n\
         verifier_reload_seconds={:.3}\ntotal_seconds={:.3}",
        hex(QUALIFIED_CERTIFICATE_PARENT_NOVA_SUITE.suite_id().bytes()),
        prover_artifact_path.display(),
        prover_descriptor.encoded_length(),
        prover_descriptor.decoded_payload_length(),
        hex(&prover_descriptor.digest()),
        hex(&prover_sha256),
        verifier_artifact_path.display(),
        verifier_descriptor.encoded_length(),
        verifier_descriptor.decoded_payload_length(),
        hex(&verifier_descriptor.digest()),
        hex(&verifier_sha256),
        binding_seconds,
        setup_seconds,
        prover_write_seconds,
        verifier_write_seconds,
        hash_seconds,
        prover_reload_seconds,
        verifier_reload_seconds,
        started.elapsed().as_secs_f64(),
    );
}
