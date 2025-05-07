use edge_frontend::{
  noir::{convert_to_acir_field, GenericFieldElement, InputMap, InputValue},
  program::{compress, run, Switchboard, RAM, ROM},
  setup::Setup,
  Scalar,
};
use edge_prover::supernova::snark::CompressedSNARK;
use halo2curves::{ff::Field, grumpkin};

use super::*;

#[test]
#[traced_test]
fn test_ivc() {
  let programs = vec![square_zeroth()];
  // TODO: This is a hack to get the correct number of folds when there are no external inputs.
  let switchboard_inputs = vec![
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64)))]),
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64)))]),
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64)))]),
  ];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(2), Scalar::from(1)],
    0,
  );
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  dbg!(&snark.zi_primary());
  assert_eq!(snark.zi_primary()[0], Scalar::from(256));
  assert_eq!(snark.zi_primary()[1], Scalar::from(1));
}

#[test]
#[traced_test]
fn test_ivc_private_inputs() {
  let programs = vec![add_external()];
  let switchboard_inputs = vec![
    InputMap::from([
      ("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64))),
      (
        "external".to_string(),
        InputValue::Vec(vec![
          InputValue::Field(GenericFieldElement::from(3_u64)),
          InputValue::Field(GenericFieldElement::from(3_u64)),
        ]),
      ),
    ]),
    InputMap::from([
      ("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64))),
      (
        "external".to_string(),
        InputValue::Vec(vec![
          InputValue::Field(GenericFieldElement::from(420_u64)),
          InputValue::Field(GenericFieldElement::from(69_u64)),
        ]),
      ),
    ]),
  ];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(1), Scalar::from(2), Scalar::from(3), Scalar::from(4), Scalar::from(5), Scalar::from(6), Scalar::from(7), Scalar::from(8), Scalar::from(9), Scalar::from(10), Scalar::from(11),],
    0,
  );
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  let zi = snark.zi_primary();
  dbg!(zi);
  // 1 + 3 + 420 == 424
  // 2 + 3 + 69 == 74
  assert_eq!(zi[0], Scalar::from(424));
  assert_eq!(zi[1], Scalar::from(74));
}

#[test]
#[traced_test]
fn test_nivc() {
  let programs = vec![add_external(), square_zeroth(), swap_memory()];
  let switchboard_inputs = vec![
    InputMap::from([
      ("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(1_u64))),
      (
        "external".to_string(),
        InputValue::Vec(vec![
          InputValue::Field(GenericFieldElement::from(5_u64)),
          InputValue::Field(GenericFieldElement::from(7_u64)),
        ]),
      ),
    ]),
    InputMap::from([("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(2_u64)))]),
    InputMap::from([(
      "next_pc".to_string(),
      InputValue::Field(GenericFieldElement::from(-1_i128)),
    )]),
  ];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(1), Scalar::from(2), Scalar::from(3), Scalar::from(4), Scalar::from(5), Scalar::from(6), Scalar::from(7), Scalar::from(8), Scalar::from(9), Scalar::from(10), Scalar::from(11),],
    0,
  );
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  let zi = snark.zi_primary();
  dbg!(zi);
  // First fold:
  // step_out[0] == 1 + 5 == 6
  // step_out[1] == 2 + 7 == 9
  // Second fold:
  // step_out[0] == 6 ** 2 == 36
  // step_out[1] == 9
  // Third fold:
  // step_out[0] == 9
  // step_out[1] == 36
  assert_eq!(zi[0], Scalar::from(9));
  assert_eq!(zi[1], Scalar::from(36));
}

#[test]
#[traced_test]
fn test_ivc_verify() {
  let programs = vec![square_zeroth()];
  let switchboard_inputs = vec![InputMap::from([(
    "next_pc".to_string(),
    InputValue::Field(GenericFieldElement::from(0_u64)),
  )])];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(2), Scalar::from(1)],
    0,
  );
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  let (z1_primary, z1_secondary) =
    snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
  assert_eq!(&z1_primary, snark.zi_primary());
  assert_eq!(&z1_secondary, snark.zi_secondary());
  assert_eq!(z1_primary, vec![Scalar::from(4), Scalar::from(1)]);
  assert_eq!(z1_secondary, vec![grumpkin::Fr::ZERO]);
}

// TODO: Lots of clones here now.
#[test]
#[traced_test]
fn test_ivc_compression() {
  let programs = vec![square_zeroth()];
  let switchboard_inputs = vec![InputMap::from([(
    "next_pc".to_string(),
    InputValue::Field(GenericFieldElement::from(0_u64)),
  )])];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(2), Scalar::from(1)],
    0,
  );
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  let compressed_proof = compress(&setup, &snark).unwrap();

  let (_, vk) = CompressedSNARK::setup(&setup.params).unwrap();
  compressed_proof.verify(&setup.params, &vk, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
}

#[test]
#[traced_test]
fn test_ivc_verify_basic() {
  let programs = vec![basic()];
  let switchboard_inputs = vec![InputMap::from([
    ("external_mul".to_string(), InputValue::Field(GenericFieldElement::from(3_u64))),
    ("external_add".to_string(), InputValue::Field(GenericFieldElement::from(10_u64))),
  ])];
  let switchboard = Switchboard::<ROM>::new(programs, switchboard_inputs, vec![Scalar::from(2)], 0);
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  let (z1_primary, z1_secondary) =
    snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
  assert_eq!(&z1_primary, snark.zi_primary());
  assert_eq!(&z1_secondary, snark.zi_secondary());
  assert_eq!(z1_primary, vec![Scalar::from(436)]);
  assert_eq!(z1_secondary, vec![grumpkin::Fr::ZERO]);
}

#[test]
#[traced_test]
fn test_ivc_compression_basic() {
  let programs = vec![basic()];
  let switchboard_inputs = vec![InputMap::from([
    ("external_mul".to_string(), InputValue::Field(GenericFieldElement::from(3_u64))),
    ("external_add".to_string(), InputValue::Field(GenericFieldElement::from(10_u64))),
  ])];
  let switchboard = Switchboard::<ROM>::new(programs, switchboard_inputs, vec![Scalar::from(2)], 0);
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  let (z1_primary, z1_secondary) =
    snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
  dbg!(&z1_primary); // 0x1b4
  dbg!(&z1_secondary); // 0x0
  let compressed_proof = compress(&setup, &snark).unwrap();
  let (_, vk) = CompressedSNARK::setup(&setup.params).unwrap();
  compressed_proof.verify(&setup.params, &vk, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
}

#[test]
#[traced_test]
fn test_ivc_verify_poseidon() {
  let programs = vec![poseidon()];
  let switchboard_inputs = vec![InputMap::new()];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(2), Scalar::from(1)],
    0,
  );
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  let (z1_primary, z1_secondary) =
    snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
  assert_eq!(&z1_primary, snark.zi_primary());
  assert_eq!(&z1_secondary, snark.zi_secondary());
}

#[test]
#[traced_test]
fn test_ivc_compression_poseidon() {
  let programs = vec![poseidon()];
  let switchboard_inputs = vec![InputMap::new()];
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    vec![Scalar::from(2), Scalar::from(1)],
    0,
  );
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  let compressed_proof = compress(&setup, &snark).unwrap();

  let (_, vk) = CompressedSNARK::setup(&setup.params).unwrap();
  compressed_proof.verify(&setup.params, &vk, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
}

#[test]
#[traced_test]
fn test_collatz() {
  let programs = vec![collatz_even(), collatz_odd()];
  let collatz_start = 19;
  let initial_circuit_index = collatz_start % 2;
  let switchboard = Switchboard::<RAM>::new(
    programs,
    vec![Scalar::from(collatz_start)],
    initial_circuit_index as usize,
  );
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  let (z1_primary, z1_secondary) =
    snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
  dbg!(&z1_primary);
  dbg!(&snark.program_counter());
  assert_eq!(&z1_primary, snark.zi_primary());
  assert_eq!(&z1_secondary, snark.zi_secondary());

  let compressed_proof = compress(&setup, &snark).unwrap();
  let (_, vk) = CompressedSNARK::setup(&setup.params).unwrap();
  compressed_proof.verify(&setup.params, &vk, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
}

#[test]
#[traced_test]
fn test_ivc_plaintext_authentication() {
  let programs = vec![plaintext_authentication()];
  let request_inputs = one_block_request_inputs();
  let keys = vec![
    50462976,
    117835012,
    185207048,
    252579084,
    319951120,
    387323156,
    454695192,
    522067228,
  ];
  let nonce = vec![0, 74, 0];
  let ciphertext_digest = Scalar::from_raw([0x90388e84c482a56b, 0x9581e2342c863840, 0xe97232ce14e7a773, 0x0534bbfb66d6f67b]);

  let switchboard_inputs = vec![
    InputMap::from([
      (
        "ciphertext_digest".to_string(),
        InputValue::Field(convert_to_acir_field(ciphertext_digest)),
      ),
      ("counter".to_string(), InputValue::Field(GenericFieldElement::from(0_u64))),
      ("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(-1_i128))),
      ("key".to_string(), InputValue::Vec(keys.iter().map(|k| InputValue::Field(GenericFieldElement::from(*k as u64))).collect())),
      ("nonce".to_string(), InputValue::Vec(nonce.iter().map(|n| InputValue::Field(GenericFieldElement::from(*n as u64))).collect())),
      ("plaintext".to_string(), InputValue::Vec(request_inputs.plaintext[0].iter().map(|p| InputValue::Field(GenericFieldElement::from(*p as u64))).collect())),
    ]),
  ];
  let initial_nivc_input = vec![
    ciphertext_digest,
    Scalar::from(1),
    Scalar::from(1),
    Scalar::from_raw([0xce84acba3d8f890f, 0x0879ef3620d7870f, 0x274926ac72df2fa8, 0x1d783777ffc2c504]),
    Scalar::from_raw([0xf76a4c5afa465bb8, 0x882ae91f44335037, 0x44a11442d0b93142, 0x08e9414b8831fb98]),
    Scalar::from(6),
    Scalar::from(0),
    Scalar::from(1),
    Scalar::from(0),
    Scalar::from_raw([0x7546e43a7231dac3, 0x313ebce4de805951, 0x3d9003310dd1c909, 0x072c5a3f63e524e4]),
    Scalar::from(0),
  ];
  let initial_circuit_index = 0;
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    initial_nivc_input,
    initial_circuit_index,
  );
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  // let (z1_primary, z1_secondary) =
  //   snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
}

#[test]
#[traced_test]
fn test_ivc_plaintext_authentication_split() {
  let programs = vec![plaintext_authentication()];
  let request_inputs = one_block_request_inputs();
  let keys = vec![
    50462976,
    117835012,
    185207048,
    252579084,
    319951120,
    387323156,
    454695192,
    522067228,
  ];
  let nonce = vec![0, 74, 0];
  let ciphertext_digest = Scalar::from_raw([0x90388e84c482a56b, 0x9581e2342c863840, 0xe97232ce14e7a773, 0x0534bbfb66d6f67b]);
  // 64 bytes
  let block2 = vec![
    0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20,
  ];
  let mut padded_vec = block2.iter()
    .map(|p| InputValue::Field(GenericFieldElement::from(*p as u64)))
    .collect::<Vec<_>>();
  padded_vec.resize(64, InputValue::Field(GenericFieldElement::from(-1i128)));

  let switchboard_inputs = vec![
    InputMap::from([
      (
        "ciphertext_digest".to_string(),
        InputValue::Field(convert_to_acir_field(ciphertext_digest)),
      ),
      ("counter".to_string(), InputValue::Field(GenericFieldElement::from(0_u64))),
      ("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(0_u64))),
      ("key".to_string(), InputValue::Vec(keys.iter().map(|k| InputValue::Field(GenericFieldElement::from(*k as u64))).collect())),
      ("nonce".to_string(), InputValue::Vec(nonce.iter().map(|n| InputValue::Field(GenericFieldElement::from(*n as u64))).collect())),
      ("plaintext".to_string(), InputValue::Vec(request_inputs.plaintext[0].iter().map(|p| InputValue::Field(GenericFieldElement::from(*p as u64))).collect())),
    ]),
    InputMap::from([
      (
        "ciphertext_digest".to_string(),
        InputValue::Field(convert_to_acir_field(ciphertext_digest)),
      ),
      ("counter".to_string(), InputValue::Field(GenericFieldElement::from(1_u64))),
      ("next_pc".to_string(), InputValue::Field(GenericFieldElement::from(-1_i128))),
      ("key".to_string(), InputValue::Vec(keys.iter().map(|k| InputValue::Field(GenericFieldElement::from(*k as u64))).collect())),
      ("nonce".to_string(), InputValue::Vec(nonce.iter().map(|n| InputValue::Field(GenericFieldElement::from(*n as u64))).collect())),
      ("plaintext".to_string(), InputValue::Vec(padded_vec)),
    ]),
  ];
  let initial_nivc_input = vec![
    ciphertext_digest,
    Scalar::from(1),
    Scalar::from(1),
    // 0x14ecfaf8d7323cb2015189ca786a7a585e932dfba83c98d97b8bf22b95aeb257
    Scalar::from_raw([0x7b8bf22b95aeb257, 0x5e932dfba83c98d9, 0x015189ca786a7a58, 0x14ecfaf8d7323cb2]),
    // 0x12e3cd05d02c32d340e5bf0fa57f2d1da758063cee65e60de5778fb75242b05d
    Scalar::from_raw([0xe5778fb75242b05d, 0xa758063cee65e60d, 0x40e5bf0fa57f2d1d, 0x12e3cd05d02c32d3]),
    Scalar::from(6),
    Scalar::from(0),
    Scalar::from(1),
    Scalar::from(0),
    Scalar::from_raw([0x430ad4db7aa84aa3, 0x03727e9b219b746e, 0x031ea5cd2b367dee, 0x1e0204c740cb79c6]),
    Scalar::from(0),
  ];
  let initial_circuit_index = 0;
  let switchboard = Switchboard::<ROM>::new(
    programs,
    switchboard_inputs,
    initial_nivc_input,
    initial_circuit_index,
  );
  let setup = Setup::new(switchboard).unwrap();
  let snark = run(&setup).unwrap();
  // let (z1_primary, z1_secondary) =
  //   snark.verify(&setup.params, &snark.z0_primary(), &snark.z0_secondary()).unwrap();
}

#[derive(Clone)]
pub struct EncryptionInput {
  /// 128-bit key
  pub key:        Vec<u8>,
  /// 96-bit IV
  pub iv:         [u8; 12],
  /// 128-bit AAD
  pub aad:        Vec<u8>,
  /// plaintext to be encrypted
  pub plaintext:  Vec<Vec<u8>>,
  /// ciphertext associated with plaintext
  pub ciphertext: Vec<Vec<u8>>,
  /// nonce sequence number
  pub seq:        u64,
}

// Case from test_chacha20_setup_16_block
// plaintext is 64 bytes
// https://github.com/elysia-dev/noir-web-prover-circuits/blob/feat/chacha20/chacha20/src/tests.nr#L67
pub(crate) fn one_block_request_inputs() -> EncryptionInput {
  EncryptionInput {
    plaintext: vec![vec![
      0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74,
      0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
      0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20,
      0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
      0x6f, 0x75, 0x20, 0x6f,
    ],
    vec![0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, ],
    ],
    ciphertext: vec![vec![
      0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69,
      0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f,
      0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd,
      0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
      0x9f, 0x08, 0x61, 0xd8,
    ]],
    key: vec![
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ],
    iv: [0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    aad: vec![0; 16],
    seq: 0,
  }
}
