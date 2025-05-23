#![doc = include_str!("./Readme.md")]

use std::{ops::Index, sync::Arc};

use bellpepper_core::{ConstraintSystem, SynthesisError};
use ff::Field;
use itertools::Itertools as _;
use once_cell::sync::OnceCell;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
  bellpepper::{
    r1cs::{NovaShape, NovaWitness},
    shape_cs::ShapeCS,
    solver::SatisfyingAssignment,
  },
  constants::{BN_LIMB_WIDTH, BN_N_LIMBS, NUM_HASH_BITS},
  digest::{DigestComputer, SimpleDigestible},
  errors::NovaError,
  nifs::NIFS,
  r1cs::{
    self, commitment_key_size, CommitmentKeyHint, R1CSInstance, R1CSResult, R1CSShape, R1CSWitness,
    RelaxedR1CSInstance, RelaxedR1CSWitness,
  },
  scalar_as_base,
  traits::{
    commitment::{CommitmentEngineTrait, CommitmentTrait},
    AbsorbInROTrait, CurveCycleEquipped, Dual, Engine, ROConstants, ROConstantsCircuit, ROTrait,
  },
  Commitment, CommitmentKey, R1CSWithArity,
};

mod circuit; // declare the module first
pub use circuit::{StepCircuit, SuperNovaAugmentedCircuitParams, TrivialCircuit};
use circuit::{SuperNovaAugmentedCircuit, SuperNovaAugmentedCircuitInputs};
use error::SuperNovaError;

/// A struct that manages all the digests of the primary circuits of a SuperNova
/// instance
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct CircuitDigests<E: Engine> {
  digests: Vec<E::Scalar>,
}

impl<E: Engine> SimpleDigestible for CircuitDigests<E> {}

impl<E: Engine> std::ops::Deref for CircuitDigests<E> {
  type Target = Vec<E::Scalar>;

  fn deref(&self) -> &Self::Target { &self.digests }
}

impl<E: Engine> CircuitDigests<E> {
  /// Construct a new [`CircuitDigests`]
  pub fn new(digests: Vec<E::Scalar>) -> Self { Self { digests } }

  /// Return the [`CircuitDigests`]' digest.
  pub fn digest(&self) -> E::Scalar {
    let dc: DigestComputer<'_, <E as Engine>::Scalar, Self> = DigestComputer::new(self);
    dc.digest().expect("Failure in computing digest")
  }
}

/// A vector of [`R1CSWithArity`] adjoined to a set of [`PublicParams`]
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PublicParams<E1>
where E1: CurveCycleEquipped {
  /// The internal circuit shapes
  circuit_shapes: Vec<R1CSWithArity<E1>>,

  ro_consts_primary: ROConstants<E1>,
  ro_consts_circuit_primary: ROConstantsCircuit<Dual<E1>>,
  ck_primary: Arc<CommitmentKey<E1>>, // This is shared between all circuit params
  augmented_circuit_params_primary: SuperNovaAugmentedCircuitParams,

  ro_consts_secondary: ROConstants<Dual<E1>>,
  ro_consts_circuit_secondary: ROConstantsCircuit<E1>,
  ck_secondary: Arc<CommitmentKey<Dual<E1>>>,
  circuit_shape_secondary: R1CSWithArity<Dual<E1>>,
  augmented_circuit_params_secondary: SuperNovaAugmentedCircuitParams,

  /// Digest constructed from this `PublicParams`' parameters
  #[serde(skip, default = "OnceCell::new")]
  digest: OnceCell<E1::Scalar>,
}

/// Auxiliary [`PublicParams`] information about the commitment keys and
/// secondary circuit. This is used as a helper struct when reconstructing
/// [`PublicParams`] downstream in lurk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AuxParams<E1>
where E1: CurveCycleEquipped {
  pub ro_consts_primary: ROConstants<E1>,
  pub ro_consts_circuit_primary: ROConstantsCircuit<Dual<E1>>,
  pub ck_primary: Arc<CommitmentKey<E1>>, // This is shared between all circuit params
  pub augmented_circuit_params_primary: SuperNovaAugmentedCircuitParams,

  pub ro_consts_secondary: ROConstants<Dual<E1>>,
  pub ro_consts_circuit_secondary: ROConstantsCircuit<E1>,
  pub ck_secondary: Arc<CommitmentKey<Dual<E1>>>,
  pub circuit_shape_secondary: R1CSWithArity<Dual<E1>>,
  pub augmented_circuit_params_secondary: SuperNovaAugmentedCircuitParams,

  pub digest: E1::Scalar,
}

use std::io::Cursor;

use crate::{
  fast_serde,
  fast_serde::{FastSerde, SerdeByteError, SerdeByteTypes},
};

impl<E1> FastSerde for AuxParams<E1>
where
  E1: CurveCycleEquipped,
  <E1::CE as CommitmentEngineTrait<E1>>::CommitmentKey: FastSerde,
  <<E1::Secondary as Engine>::CE as CommitmentEngineTrait<E1::Secondary>>::CommitmentKey: FastSerde,
{
  /// Byte format:
  /// [0..4]   - Magic number (4 bytes)
  /// [4]      - Serde type: AuxParams (u8)
  /// [5]      - Number of sections (u8 = 8)
  /// Sections (repeated 8 times):
  ///   [N]      - Section type (u8)
  ///   [N+1..5] - Section size (u32)
  ///   [N+5..]  - Section data (variable length)
  /// Section types:
  ///   1: ro_consts_primary (bincode)
  ///   2: ro_consts_circuit_primary (bincode)
  ///   3: ck_primary (FastSerde)
  ///   4: ro_consts_secondary (bincode)
  ///   5: ro_consts_circuit_secondary (bincode)
  ///   6: ck_secondary (FastSerde)
  ///   7: circuit_shape_secondary (json)
  ///   8: digest (bincode)
  fn to_bytes(&self) -> Vec<u8> {
    let mut out = Vec::new();

    // Write header
    out.extend_from_slice(&fast_serde::MAGIC_NUMBER);
    out.push(fast_serde::SerdeByteTypes::AuxParams as u8);
    out.push(8); // num_sections

    // Write sections
    Self::write_section_bytes(&mut out, 1, &bincode::serialize(&self.ro_consts_primary).unwrap());
    Self::write_section_bytes(
      &mut out,
      2,
      &bincode::serialize(&self.ro_consts_circuit_primary).unwrap(),
    );
    Self::write_section_bytes(&mut out, 3, &self.ck_primary.to_bytes());
    Self::write_section_bytes(&mut out, 4, &bincode::serialize(&self.ro_consts_secondary).unwrap());
    Self::write_section_bytes(
      &mut out,
      5,
      &bincode::serialize(&self.ro_consts_circuit_secondary).unwrap(),
    );
    Self::write_section_bytes(&mut out, 6, &self.ck_secondary.to_bytes());
    Self::write_section_bytes(
      &mut out,
      7,
      &bincode::serialize(&self.circuit_shape_secondary).unwrap(),
    );
    Self::write_section_bytes(&mut out, 8, &bincode::serialize(&self.digest).unwrap());

    out
  }

  fn from_bytes(bytes: &[u8]) -> Result<Self, SerdeByteError> {
    let mut cursor = Cursor::new(bytes);

    // Validate header
    Self::validate_header(&mut cursor, SerdeByteTypes::AuxParams, 8)?;

    // Read all sections
    let ro_consts_primary = bincode::deserialize(&Self::read_section_bytes(&mut cursor, 1)?)?;
    let ro_consts_circuit_primary =
      bincode::deserialize(&Self::read_section_bytes(&mut cursor, 2)?)?;
    let ck_primary = Arc::new(<E1::CE as CommitmentEngineTrait<E1>>::CommitmentKey::from_bytes(
      &Self::read_section_bytes(&mut cursor, 3)?,
    )?);
    let ro_consts_secondary = bincode::deserialize(&Self::read_section_bytes(&mut cursor, 4)?)?;
    let ro_consts_circuit_secondary =
      bincode::deserialize(&Self::read_section_bytes(&mut cursor, 5)?)?;
    let ck_secondary = Arc::new(<<E1::Secondary as Engine>::CE as CommitmentEngineTrait<
      E1::Secondary,
    >>::CommitmentKey::from_bytes(&Self::read_section_bytes(
      &mut cursor,
      6,
    )?)?);
    let circuit_shape_secondary = bincode::deserialize(&Self::read_section_bytes(&mut cursor, 7)?)?;
    let digest = bincode::deserialize(&Self::read_section_bytes(&mut cursor, 8)?)?;

    // NOTE: This does not check the digest. Maybe we should.
    Ok(Self {
      ro_consts_primary,
      ro_consts_circuit_primary,
      ck_primary,
      augmented_circuit_params_primary: SuperNovaAugmentedCircuitParams::new(
        BN_LIMB_WIDTH,
        BN_N_LIMBS,
        true,
      ),
      ro_consts_secondary,
      ro_consts_circuit_secondary,
      ck_secondary,
      circuit_shape_secondary,
      augmented_circuit_params_secondary: SuperNovaAugmentedCircuitParams::new(
        BN_LIMB_WIDTH,
        BN_N_LIMBS,
        false,
      ),
      digest,
    })
  }
}

impl<E1> Index<usize> for PublicParams<E1>
where E1: CurveCycleEquipped
{
  type Output = R1CSWithArity<E1>;

  fn index(&self, index: usize) -> &Self::Output { &self.circuit_shapes[index] }
}

impl<E1> SimpleDigestible for PublicParams<E1> where E1: CurveCycleEquipped {}

impl<E1> PublicParams<E1>
where E1: CurveCycleEquipped
{
  /// Construct a new [`PublicParams`]
  ///
  /// # Note
  ///
  /// Public parameters set up a number of bases for the homomorphic
  /// commitment scheme of Nova.
  ///
  /// Some final compressing SNARKs, like variants of Spartan, use computation
  /// commitments that require larger sizes for these parameters. These
  /// SNARKs provide a hint for these values by implementing
  /// `RelaxedR1CSSNARKTrait::commitment_key_floor()`, which can be passed to
  /// this function.
  ///
  /// If you're not using such a SNARK, pass `&(|_| 0)` instead.
  ///
  /// # Arguments
  ///
  /// * `non_uniform_circuit`: The non-uniform circuit of type `NC`.
  /// * `ck_hint1`: A `CommitmentKeyHint` for `E1`, which is a function that provides a hint for the
  ///   number of generators required in the commitment scheme for the primary circuit.
  /// * `ck_hint2`: A `CommitmentKeyHint` for `E2`, similar to `ck_hint1`, but for the secondary
  ///   circuit.
  pub fn setup<NC: NonUniformCircuit<E1>>(
    non_uniform_circuit: &NC,
    ck_hint1: &CommitmentKeyHint<E1>,
    ck_hint2: &CommitmentKeyHint<Dual<E1>>,
  ) -> Self {
    let num_circuits = non_uniform_circuit.num_circuits();

    let augmented_circuit_params_primary =
      SuperNovaAugmentedCircuitParams::new(BN_LIMB_WIDTH, BN_N_LIMBS, true);
    let ro_consts_primary: ROConstants<E1> = ROConstants::<E1>::default();
    // ro_consts_circuit_primary are parameterized by E2 because the type alias uses
    // E2::Base = E1::Scalar
    let ro_consts_circuit_primary: ROConstantsCircuit<Dual<E1>> =
      ROConstantsCircuit::<Dual<E1>>::default();

    let circuit_shapes = get_circuit_shapes(non_uniform_circuit);

    let ck_primary = Self::compute_primary_ck(&circuit_shapes, ck_hint1);
    let ck_primary = Arc::new(ck_primary);

    let augmented_circuit_params_secondary =
      SuperNovaAugmentedCircuitParams::new(BN_LIMB_WIDTH, BN_N_LIMBS, false);
    let ro_consts_secondary = ROConstants::<Dual<E1>>::default();
    let c_secondary = non_uniform_circuit.secondary_circuit();
    let F_arity_secondary = c_secondary.arity();
    let ro_consts_circuit_secondary: ROConstantsCircuit<E1> = ROConstantsCircuit::<E1>::default();

    let circuit_secondary: SuperNovaAugmentedCircuit<'_, E1, NC::C2> =
      SuperNovaAugmentedCircuit::new(
        &augmented_circuit_params_secondary,
        None,
        &c_secondary,
        ro_consts_circuit_secondary.clone(),
        num_circuits,
      );
    let mut cs: ShapeCS<Dual<E1>> = ShapeCS::new();
    circuit_secondary.synthesize(&mut cs).expect("circuit synthesis failed");
    let (r1cs_shape_secondary, ck_secondary) = cs.r1cs_shape_and_key(ck_hint2);
    let ck_secondary = Arc::new(ck_secondary);
    let circuit_shape_secondary = R1CSWithArity::new(r1cs_shape_secondary, F_arity_secondary);

    let pp = Self {
      circuit_shapes,
      ro_consts_primary,
      ro_consts_circuit_primary,
      ck_primary,
      augmented_circuit_params_primary,
      ro_consts_secondary,
      ro_consts_circuit_secondary,
      ck_secondary,
      circuit_shape_secondary,
      augmented_circuit_params_secondary,
      digest: OnceCell::new(),
    };

    // make sure to initialize the `OnceCell` and compute the digest
    // and avoid paying for unexpected performance costs later
    pp.digest();
    pp
  }

  /// Breaks down an instance of [`PublicParams`] into the circuit params and
  /// auxiliary params.
  pub fn into_parts(self) -> (Vec<R1CSWithArity<E1>>, AuxParams<E1>) {
    let digest = self.digest();

    let Self {
      circuit_shapes,
      ro_consts_primary,
      ro_consts_circuit_primary,
      ck_primary,
      augmented_circuit_params_primary,
      ro_consts_secondary,
      ro_consts_circuit_secondary,
      ck_secondary,
      circuit_shape_secondary,
      augmented_circuit_params_secondary,
      digest: _digest,
    } = self;

    let aux_params = AuxParams {
      ro_consts_primary,
      ro_consts_circuit_primary,
      ck_primary,
      augmented_circuit_params_primary,
      ro_consts_secondary,
      ro_consts_circuit_secondary,
      ck_secondary,
      circuit_shape_secondary,
      augmented_circuit_params_secondary,
      digest,
    };

    (circuit_shapes, aux_params)
  }

  /// Returns just the [`AuxParams`] portion of [`PublicParams`] from a
  /// reference to [`PublicParams`].
  pub fn aux_params(&self) -> AuxParams<E1> {
    AuxParams {
      ro_consts_primary: self.ro_consts_primary.clone(),
      ro_consts_circuit_primary: self.ro_consts_circuit_primary.clone(),
      ck_primary: self.ck_primary.clone(),
      augmented_circuit_params_primary: self.augmented_circuit_params_primary.clone(),
      ro_consts_secondary: self.ro_consts_secondary.clone(),
      ro_consts_circuit_secondary: self.ro_consts_circuit_secondary.clone(),
      ck_secondary: self.ck_secondary.clone(),
      circuit_shape_secondary: self.circuit_shape_secondary.clone(),
      augmented_circuit_params_secondary: self.augmented_circuit_params_secondary.clone(),
      digest: self.digest(),
    }
  }

  /// Create a [`PublicParams`] from a vector of raw [`R1CSWithArity`] and
  /// auxiliary params.
  pub fn from_parts(circuit_shapes: Vec<R1CSWithArity<E1>>, aux_params: AuxParams<E1>) -> Self {
    let pp = Self {
      circuit_shapes,
      ro_consts_primary: aux_params.ro_consts_primary,
      ro_consts_circuit_primary: aux_params.ro_consts_circuit_primary,
      ck_primary: aux_params.ck_primary,
      augmented_circuit_params_primary: aux_params.augmented_circuit_params_primary,
      ro_consts_secondary: aux_params.ro_consts_secondary,
      ro_consts_circuit_secondary: aux_params.ro_consts_circuit_secondary,
      ck_secondary: aux_params.ck_secondary,
      circuit_shape_secondary: aux_params.circuit_shape_secondary,
      augmented_circuit_params_secondary: aux_params.augmented_circuit_params_secondary,
      digest: OnceCell::new(),
    };
    assert_eq!(
      aux_params.digest,
      pp.digest(),
      "param data is invalid; aux_params contained the incorrect digest"
    );
    pp
  }

  /// Create a [`PublicParams`] from a vector of raw [`R1CSWithArity`] and
  /// auxiliary params. We don't check that the `aux_params.digest` is a
  /// valid digest for the created params.
  pub fn from_parts_unchecked(
    circuit_shapes: Vec<R1CSWithArity<E1>>,
    aux_params: AuxParams<E1>,
  ) -> Self {
    Self {
      circuit_shapes,
      ro_consts_primary: aux_params.ro_consts_primary,
      ro_consts_circuit_primary: aux_params.ro_consts_circuit_primary,
      ck_primary: aux_params.ck_primary,
      augmented_circuit_params_primary: aux_params.augmented_circuit_params_primary,
      ro_consts_secondary: aux_params.ro_consts_secondary,
      ro_consts_circuit_secondary: aux_params.ro_consts_circuit_secondary,
      ck_secondary: aux_params.ck_secondary,
      circuit_shape_secondary: aux_params.circuit_shape_secondary,
      augmented_circuit_params_secondary: aux_params.augmented_circuit_params_secondary,
      digest: aux_params.digest.into(),
    }
  }

  /// Compute primary and secondary commitment keys sized to handle the
  /// largest of the circuits in the provided `R1CSWithArity`.
  fn compute_primary_ck(
    circuit_params: &[R1CSWithArity<E1>],
    ck_hint1: &CommitmentKeyHint<E1>,
  ) -> CommitmentKey<E1> {
    let size_primary = circuit_params
      .iter()
      .map(|circuit| commitment_key_size(&circuit.r1cs_shape, ck_hint1))
      .max()
      .unwrap();

    E1::CE::setup(b"ck", size_primary)
  }

  /// Return the [`PublicParams`]' digest.
  pub fn digest(&self) -> E1::Scalar {
    self
      .digest
      .get_or_try_init(|| {
        let dc: DigestComputer<'_, <E1 as Engine>::Scalar, Self> = DigestComputer::new(self);
        dc.digest()
      })
      .cloned()
      .expect("Failure in retrieving digest")
  }

  /// Returns the number of constraints and variables of inner circuit based
  /// on index
  pub fn num_constraints_and_variables(&self, index: usize) -> (usize, usize) {
    (self.circuit_shapes[index].r1cs_shape.num_cons, self.circuit_shapes[index].r1cs_shape.num_vars)
  }

  /// Returns the number of constraints and variables of the secondary circuit
  pub fn num_constraints_and_variables_secondary(&self) -> (usize, usize) {
    (
      self.circuit_shape_secondary.r1cs_shape.num_cons,
      self.circuit_shape_secondary.r1cs_shape.num_vars,
    )
  }

  /// All of the primary circuit digests of this [`PublicParams`]
  pub fn circuit_param_digests(&self) -> CircuitDigests<E1> {
    let digests = self.circuit_shapes.iter().map(|cp| cp.digest()).collect::<Vec<_>>();
    CircuitDigests { digests }
  }

  /// Returns all the primary R1CS Shapes
  fn primary_r1cs_shapes(&self) -> Vec<&R1CSShape<E1>> {
    self.circuit_shapes.iter().map(|cs| &cs.r1cs_shape).collect::<Vec<_>>()
  }
}

pub fn get_circuit_shapes<E1: CurveCycleEquipped, NC: NonUniformCircuit<E1>>(
  non_uniform_circuit: &NC,
) -> Vec<R1CSWithArity<E1>> {
  let num_circuits = non_uniform_circuit.num_circuits();
  let augmented_circuit_params_primary =
    SuperNovaAugmentedCircuitParams::new(BN_LIMB_WIDTH, BN_N_LIMBS, true);

  // ro_consts_circuit_primary are parameterized by E2 because the type alias uses
  // E2::Base = E1::Scalar
  let ro_consts_circuit_primary: ROConstantsCircuit<Dual<E1>> =
    ROConstantsCircuit::<Dual<E1>>::default();

  (0..num_circuits)
    .map(|i| {
      let c_primary = non_uniform_circuit.primary_circuit(i);
      let F_arity = c_primary.arity();
      // Initialize ck for the primary
      let circuit_primary: SuperNovaAugmentedCircuit<'_, Dual<E1>, NC::C1> =
        SuperNovaAugmentedCircuit::new(
          &augmented_circuit_params_primary,
          None,
          &c_primary,
          ro_consts_circuit_primary.clone(),
          num_circuits,
        );
      let mut cs: ShapeCS<E1> = ShapeCS::new();
      circuit_primary.synthesize(&mut cs).expect("circuit synthesis failed");

      // We use the largest commitment_key for all instances
      let r1cs_shape_primary = cs.r1cs_shape();
      R1CSWithArity::new(r1cs_shape_primary, F_arity)
    })
    .collect::<Vec<_>>()
}

/// A resource buffer for SuperNova's [`RecursiveSNARK`] for storing scratch
/// values that are computed by `prove_step`, which allows the reuse of memory
/// allocations and avoids unnecessary new allocations in the critical section.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
struct ResourceBuffer<E: Engine> {
  l_w: Option<R1CSWitness<E>>,
  l_u: Option<R1CSInstance<E>>,

  ABC_Z_1: R1CSResult<E>,
  ABC_Z_2: R1CSResult<E>,

  /// buffer for `commit_T`
  T: Vec<E::Scalar>,
}

/// A SNARK that proves the correct execution of an non-uniform incremental
/// computation
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct RecursiveSNARK<E1>
where E1: CurveCycleEquipped {
  // Cached digest of the public parameters
  pp_digest:              E1::Scalar,
  num_augmented_circuits: usize,

  // Number of iterations performed up to now
  i: usize,

  // Inputs and outputs of the primary circuits
  z0_primary: Vec<E1::Scalar>,
  zi_primary: Vec<E1::Scalar>,

  // Proven circuit index, and current program counter
  proven_circuit_index: usize,
  program_counter:      E1::Scalar,

  /// Buffer for memory needed by the primary fold-step
  buffer_primary:   ResourceBuffer<E1>,
  /// Buffer for memory needed by the secondary fold-step
  buffer_secondary: ResourceBuffer<Dual<E1>>,

  // Relaxed instances for the primary circuits
  // Entries are `None` if the circuit has not been executed yet
  r_W_primary: Vec<Option<RelaxedR1CSWitness<E1>>>,
  r_U_primary: Vec<Option<RelaxedR1CSInstance<E1>>>,

  // Inputs and outputs of the secondary circuit
  z0_secondary:  Vec<<Dual<E1> as Engine>::Scalar>,
  zi_secondary:  Vec<<Dual<E1> as Engine>::Scalar>,
  // Relaxed instance for the secondary circuit
  r_W_secondary: RelaxedR1CSWitness<Dual<E1>>,
  r_U_secondary: RelaxedR1CSInstance<Dual<E1>>,
  // Proof for the secondary circuit to be accumulated into r_secondary in the next iteration
  l_w_secondary: R1CSWitness<Dual<E1>>,
  l_u_secondary: R1CSInstance<Dual<E1>>,
}

impl<E1> RecursiveSNARK<E1>
where E1: CurveCycleEquipped
{
  /// iterate base step to get new instance of recursive SNARK
  #[allow(clippy::too_many_arguments)]
  pub fn new<C0: NonUniformCircuit<E1>>(
    pp: &PublicParams<E1>,
    non_uniform_circuit: &C0,
    c_primary: &C0::C1,
    c_secondary: &C0::C2,
    z0_primary: &[E1::Scalar],
    z0_secondary: &[<Dual<E1> as Engine>::Scalar],
  ) -> Result<Self, SuperNovaError> {
    let num_augmented_circuits = non_uniform_circuit.num_circuits();
    let circuit_index = non_uniform_circuit.initial_circuit_index();

    let r1cs_secondary = &pp.circuit_shape_secondary.r1cs_shape;

    // check the length of the secondary initial input
    if z0_secondary.len() != pp.circuit_shape_secondary.F_arity {
      return Err(SuperNovaError::NovaError(NovaError::InvalidStepOutputLength));
    }

    // check the arity of all the primary circuits match the initial input length
    pp.circuit_shapes.iter().try_for_each(|circuit| {
      if circuit.F_arity != z0_primary.len() {
        return Err(SuperNovaError::NovaError(NovaError::InvalidStepOutputLength));
      }
      Ok(())
    })?;

    // base case for the primary
    let mut cs_primary = SatisfyingAssignment::<E1>::new();
    let program_counter = E1::Scalar::from(circuit_index as u64);
    let inputs_primary: SuperNovaAugmentedCircuitInputs<'_, Dual<E1>> =
      SuperNovaAugmentedCircuitInputs::new(
        scalar_as_base::<E1>(pp.digest()),
        E1::Scalar::ZERO,
        z0_primary,
        None,                  // zi = None for basecase
        None,                  // U = [None], since no previous proofs have been computed
        None,                  // u = None since we are not verifying a secondary circuit
        None,                  // T = None since there is not proof to fold
        Some(program_counter), // pc = initial_program_counter for primary circuit
        E1::Scalar::ZERO,      // u_index is always zero for the primary circuit
      );

    let circuit_primary: SuperNovaAugmentedCircuit<'_, Dual<E1>, C0::C1> =
      SuperNovaAugmentedCircuit::new(
        &pp.augmented_circuit_params_primary,
        Some(inputs_primary),
        c_primary,
        pp.ro_consts_circuit_primary.clone(),
        num_augmented_circuits,
      );

    let (zi_primary_pc_next, zi_primary) =
      circuit_primary.synthesize(&mut cs_primary).map_err(|err| {
        debug!("err {:?}", err);
        NovaError::from(err)
      })?;
    if zi_primary.len() != pp[circuit_index].F_arity {
      return Err(SuperNovaError::NovaError(NovaError::InvalidStepOutputLength));
    }
    let (u_primary, w_primary) = cs_primary
      .r1cs_instance_and_witness(&pp[circuit_index].r1cs_shape, &pp.ck_primary)
      .map_err(|err| {
        debug!("err {:?}", err);
        err
      })?;

    // base case for the secondary
    let mut cs_secondary = SatisfyingAssignment::<Dual<E1>>::new();
    let u_primary_index = <Dual<E1> as Engine>::Scalar::from(circuit_index as u64);
    let inputs_secondary: SuperNovaAugmentedCircuitInputs<'_, E1> =
      SuperNovaAugmentedCircuitInputs::new(
        pp.digest(),
        <Dual<E1> as Engine>::Scalar::ZERO,
        z0_secondary,
        None,             // zi = None for basecase
        None,             // U = Empty list of accumulators for the primary circuits
        Some(&u_primary), // Proof for first iteration of current primary circuit
        None,             // T = None, since we just copy u_primary rather than fold it
        None,             // program_counter is always None for secondary circuit
        u_primary_index,  // index of the circuit proof u_primary
      );

    let circuit_secondary: SuperNovaAugmentedCircuit<'_, E1, C0::C2> =
      SuperNovaAugmentedCircuit::new(
        &pp.augmented_circuit_params_secondary,
        Some(inputs_secondary),
        c_secondary,
        pp.ro_consts_circuit_secondary.clone(),
        num_augmented_circuits,
      );
    let (_, zi_secondary) =
      circuit_secondary.synthesize(&mut cs_secondary).map_err(NovaError::from)?;
    if zi_secondary.len() != pp.circuit_shape_secondary.F_arity {
      return Err(NovaError::InvalidStepOutputLength.into());
    }
    let (u_secondary, w_secondary) = cs_secondary
      .r1cs_instance_and_witness(r1cs_secondary, &pp.ck_secondary)
      .map_err(|_| SuperNovaError::NovaError(NovaError::UnSat))?;

    // IVC proof for the primary circuit
    let l_w_primary = w_primary;
    let l_u_primary = u_primary;
    let r_W_primary =
      RelaxedR1CSWitness::from_r1cs_witness(&pp[circuit_index].r1cs_shape, l_w_primary);

    let r_U_primary = RelaxedR1CSInstance::from_r1cs_instance(
      &*pp.ck_primary,
      &pp[circuit_index].r1cs_shape,
      l_u_primary,
    );

    // IVC proof of the secondary circuit
    let l_w_secondary = w_secondary;
    let l_u_secondary = u_secondary;

    // Initialize relaxed instance/witness pair for the secondary circuit proofs
    let r_W_secondary = RelaxedR1CSWitness::<Dual<E1>>::default(r1cs_secondary);
    let r_U_secondary = RelaxedR1CSInstance::default(&*pp.ck_secondary, r1cs_secondary);

    // Outputs of the two circuits and next program counter thus far.
    let zi_primary = zi_primary
      .iter()
      .map(|v| v.get_value().ok_or(NovaError::from(SynthesisError::AssignmentMissing).into()))
      .collect::<Result<Vec<<E1 as Engine>::Scalar>, SuperNovaError>>()?;
    let zi_primary_pc_next =
      zi_primary_pc_next
        .expect("zi_primary_pc_next missing")
        .get_value()
        .ok_or::<SuperNovaError>(NovaError::from(SynthesisError::AssignmentMissing).into())?;
    let zi_secondary = zi_secondary
      .iter()
      .map(|v| v.get_value().ok_or(NovaError::from(SynthesisError::AssignmentMissing).into()))
      .collect::<Result<Vec<<Dual<E1> as Engine>::Scalar>, SuperNovaError>>()?;

    // handle the base case by initialize U_next in next round
    let r_W_primary_initial_list = (0..num_augmented_circuits)
      .map(|i| (i == circuit_index).then(|| r_W_primary.clone()))
      .collect::<Vec<Option<RelaxedR1CSWitness<E1>>>>();

    let r_U_primary_initial_list = (0..num_augmented_circuits)
      .map(|i| (i == circuit_index).then(|| r_U_primary.clone()))
      .collect::<Vec<Option<RelaxedR1CSInstance<E1>>>>();

    // find the largest length r1cs shape for the buffer size
    let max_num_cons =
      pp.circuit_shapes.iter().map(|circuit| circuit.r1cs_shape.num_cons).max().unwrap();

    let buffer_primary = ResourceBuffer {
      l_w:     None,
      l_u:     None,
      ABC_Z_1: R1CSResult::default(max_num_cons),
      ABC_Z_2: R1CSResult::default(max_num_cons),
      T:       r1cs::default_T::<E1>(max_num_cons),
    };

    let buffer_secondary = ResourceBuffer {
      l_w:     None,
      l_u:     None,
      ABC_Z_1: R1CSResult::default(r1cs_secondary.num_cons),
      ABC_Z_2: R1CSResult::default(r1cs_secondary.num_cons),
      T:       r1cs::default_T::<Dual<E1>>(r1cs_secondary.num_cons),
    };

    Ok(Self {
      pp_digest: pp.digest(),
      num_augmented_circuits,
      i: 0_usize, // after base case, next iteration start from 1
      z0_primary: z0_primary.to_vec(),
      zi_primary,

      proven_circuit_index: circuit_index,
      program_counter: zi_primary_pc_next,

      buffer_primary,
      buffer_secondary,

      r_W_primary: r_W_primary_initial_list,
      r_U_primary: r_U_primary_initial_list,
      z0_secondary: z0_secondary.to_vec(),
      zi_secondary,
      r_W_secondary,
      r_U_secondary,
      l_w_secondary,
      l_u_secondary,
    })
  }

  /// Inputs of the primary circuits
  pub fn z0_primary(&self) -> &Vec<E1::Scalar> { &self.z0_primary }

  /// Outputs of the primary circuits
  pub fn zi_primary(&self) -> &Vec<E1::Scalar> { &self.zi_primary }

  /// Inputs of the secondary circuits
  pub fn z0_secondary(&self) -> &Vec<<Dual<E1> as Engine>::Scalar> { &self.z0_secondary }

  /// Outputs of the secondary circuits
  pub fn zi_secondary(&self) -> &Vec<<Dual<E1> as Engine>::Scalar> { &self.zi_secondary }

  /// Current program counter
  pub fn program_counter(&self) -> E1::Scalar { self.program_counter }

  /// executing a step of the incremental computation
  #[allow(clippy::too_many_arguments)]
  #[tracing::instrument(skip_all, name = "supernova::RecursiveSNARK::prove_step")]
  pub fn prove_step<C1: StepCircuit<E1::Scalar>, C2: StepCircuit<<Dual<E1> as Engine>::Scalar>>(
    &mut self,
    pp: &PublicParams<E1>,
    c_primary: &C1,
    c_secondary: &C2,
  ) -> Result<(), SuperNovaError> {
    // First step was already done in the constructor
    if self.i == 0 {
      self.i = 1;
      return Ok(());
    }

    // save the inputs before proceeding to the `i+1`th step
    let r_U_primary_i = self.r_U_primary.clone();
    // Create single-entry accumulator list for the secondary circuit to hand to
    // SuperNovaAugmentedCircuitInputs
    let r_U_secondary_i = vec![Some(self.r_U_secondary.clone())];
    let l_u_secondary_i = self.l_u_secondary.clone();

    let circuit_index = c_primary.circuit_index();
    assert_eq!(self.program_counter, E1::Scalar::from(circuit_index as u64));

    // fold the secondary circuit's instance
    let (nifs_secondary, _) = NIFS::prove_mut(
      &*pp.ck_secondary,
      &pp.ro_consts_secondary,
      &scalar_as_base::<E1>(self.pp_digest),
      &pp.circuit_shape_secondary.r1cs_shape,
      &mut self.r_U_secondary,
      &mut self.r_W_secondary,
      &self.l_u_secondary,
      &self.l_w_secondary,
      &mut self.buffer_secondary.T,
      &mut self.buffer_secondary.ABC_Z_1,
      &mut self.buffer_secondary.ABC_Z_2,
    )
    .map_err(SuperNovaError::NovaError)?;

    let mut cs_primary = SatisfyingAssignment::<E1>::with_capacity(
      pp[circuit_index].r1cs_shape.num_io + 1,
      pp[circuit_index].r1cs_shape.num_vars,
    );
    let T = Commitment::<Dual<E1>>::decompress(&nifs_secondary.comm_T)
      .map_err(SuperNovaError::NovaError)?;
    let inputs_primary: SuperNovaAugmentedCircuitInputs<'_, Dual<E1>> =
      SuperNovaAugmentedCircuitInputs::new(
        scalar_as_base::<E1>(self.pp_digest),
        E1::Scalar::from(self.i as u64),
        &self.z0_primary,
        Some(&self.zi_primary),
        Some(&r_U_secondary_i),
        Some(&l_u_secondary_i),
        Some(&T),
        Some(self.program_counter),
        E1::Scalar::ZERO,
      );

    let circuit_primary: SuperNovaAugmentedCircuit<'_, Dual<E1>, C1> =
      SuperNovaAugmentedCircuit::new(
        &pp.augmented_circuit_params_primary,
        Some(inputs_primary),
        c_primary,
        pp.ro_consts_circuit_primary.clone(),
        self.num_augmented_circuits,
      );

    let (zi_primary_pc_next, zi_primary) =
      circuit_primary.synthesize(&mut cs_primary).map_err(NovaError::from)?;
    if zi_primary.len() != pp[circuit_index].F_arity {
      return Err(SuperNovaError::NovaError(NovaError::InvalidInitialInputLength));
    }

    let (l_u_primary, l_w_primary) = cs_primary
      .r1cs_instance_and_witness(&pp[circuit_index].r1cs_shape, &pp.ck_primary)
      .map_err(SuperNovaError::NovaError)?;

    let (r_U_primary, r_W_primary) = if let (Some(Some(r_U_primary)), Some(Some(r_W_primary))) =
      (self.r_U_primary.get_mut(circuit_index), self.r_W_primary.get_mut(circuit_index))
    {
      (r_U_primary, r_W_primary)
    } else {
      self.r_U_primary[circuit_index] =
        Some(RelaxedR1CSInstance::default(&*pp.ck_primary, &pp[circuit_index].r1cs_shape));
      self.r_W_primary[circuit_index] =
        Some(RelaxedR1CSWitness::default(&pp[circuit_index].r1cs_shape));
      (
        self.r_U_primary[circuit_index].as_mut().unwrap(),
        self.r_W_primary[circuit_index].as_mut().unwrap(),
      )
    };

    let (nifs_primary, _) = NIFS::prove_mut(
      &*pp.ck_primary,
      &pp.ro_consts_primary,
      &self.pp_digest,
      &pp[circuit_index].r1cs_shape,
      r_U_primary,
      r_W_primary,
      &l_u_primary,
      &l_w_primary,
      &mut self.buffer_primary.T,
      &mut self.buffer_primary.ABC_Z_1,
      &mut self.buffer_primary.ABC_Z_2,
    )
    .map_err(SuperNovaError::NovaError)?;

    let mut cs_secondary = SatisfyingAssignment::<Dual<E1>>::with_capacity(
      pp.circuit_shape_secondary.r1cs_shape.num_io + 1,
      pp.circuit_shape_secondary.r1cs_shape.num_vars,
    );
    let binding =
      Commitment::<E1>::decompress(&nifs_primary.comm_T).map_err(SuperNovaError::NovaError)?;
    let inputs_secondary: SuperNovaAugmentedCircuitInputs<'_, E1> =
      SuperNovaAugmentedCircuitInputs::new(
        self.pp_digest,
        <Dual<E1> as Engine>::Scalar::from(self.i as u64),
        &self.z0_secondary,
        Some(&self.zi_secondary),
        Some(&r_U_primary_i),
        Some(&l_u_primary),
        Some(&binding),
        None, // pc is always None for secondary circuit
        <Dual<E1> as Engine>::Scalar::from(circuit_index as u64),
      );

    let circuit_secondary: SuperNovaAugmentedCircuit<'_, E1, C2> = SuperNovaAugmentedCircuit::new(
      &pp.augmented_circuit_params_secondary,
      Some(inputs_secondary),
      c_secondary,
      pp.ro_consts_circuit_secondary.clone(),
      self.num_augmented_circuits,
    );
    let (_, zi_secondary) =
      circuit_secondary.synthesize(&mut cs_secondary).map_err(NovaError::from)?;
    if zi_secondary.len() != pp.circuit_shape_secondary.F_arity {
      return Err(SuperNovaError::NovaError(NovaError::InvalidInitialInputLength));
    }

    let (l_u_secondary_next, l_w_secondary_next) = cs_secondary
      .r1cs_instance_and_witness(&pp.circuit_shape_secondary.r1cs_shape, &pp.ck_secondary)?;

    // update the running instances and witnesses
    let zi_primary = zi_primary
      .iter()
      .map(|v| v.get_value().ok_or(NovaError::from(SynthesisError::AssignmentMissing).into()))
      .collect::<Result<Vec<<E1 as Engine>::Scalar>, SuperNovaError>>()?;
    let zi_primary_pc_next =
      zi_primary_pc_next
        .expect("zi_primary_pc_next missing")
        .get_value()
        .ok_or::<SuperNovaError>(NovaError::from(SynthesisError::AssignmentMissing).into())?;
    let zi_secondary = zi_secondary
      .iter()
      .map(|v| v.get_value().ok_or(NovaError::from(SynthesisError::AssignmentMissing).into()))
      .collect::<Result<Vec<<Dual<E1> as Engine>::Scalar>, SuperNovaError>>()?;

    if zi_primary.len() != pp[circuit_index].F_arity
      || zi_secondary.len() != pp.circuit_shape_secondary.F_arity
    {
      return Err(SuperNovaError::NovaError(NovaError::InvalidStepOutputLength));
    }

    self.l_w_secondary = l_w_secondary_next;
    self.l_u_secondary = l_u_secondary_next;
    self.i += 1;
    self.zi_primary = zi_primary;
    self.zi_secondary = zi_secondary;
    self.proven_circuit_index = circuit_index;
    self.program_counter = zi_primary_pc_next;
    Ok(())
  }

  /// verify recursive snark
  #[allow(clippy::type_complexity)]
  pub fn verify(
    &self,
    pp: &PublicParams<E1>,
    z0_primary: &[E1::Scalar],
    z0_secondary: &[<Dual<E1> as Engine>::Scalar],
  ) -> Result<(Vec<E1::Scalar>, Vec<<Dual<E1> as Engine>::Scalar>), SuperNovaError> {
    // number of steps cannot be zero
    if self.i == 0 {
      debug!("must verify on valid RecursiveSNARK where i > 0");
      return Err(SuperNovaError::NovaError(NovaError::ProofVerifyError));
    }

    // Check lengths of r_primary
    if self.r_U_primary.len() != self.num_augmented_circuits
      || self.r_W_primary.len() != self.num_augmented_circuits
    {
      debug!("r_primary length mismatch");
      return Err(SuperNovaError::NovaError(NovaError::ProofVerifyError));
    }

    // Check that there are no missing instance/witness pairs
    self.r_U_primary.iter().zip_eq(self.r_W_primary.iter()).enumerate().try_for_each(
      |(i, (u, w))| match (u, w) {
        (Some(_), Some(_)) | (None, None) => Ok(()),
        _ => {
          debug!("r_primary[{:?}]: mismatched instance/witness pair", i);
          Err(SuperNovaError::NovaError(NovaError::ProofVerifyError))
        },
      },
    )?;

    let circuit_index = self.proven_circuit_index;

    // check we have an instance/witness pair for the circuit_index
    if self.r_U_primary[circuit_index].is_none() {
      debug!("r_primary[{:?}]: instance/witness pair is missing", circuit_index);
      return Err(SuperNovaError::NovaError(NovaError::ProofVerifyError));
    }

    // check the (relaxed) R1CS instances public outputs.
    {
      for (i, r_U_primary_i) in self.r_U_primary.iter().enumerate() {
        if let Some(u) = r_U_primary_i {
          if u.X.len() != 2 {
            debug!("r_U_primary[{:?}] got instance length {:?} != 2", i, u.X.len(),);
            return Err(SuperNovaError::NovaError(NovaError::ProofVerifyError));
          }
        }
      }

      if self.l_u_secondary.X.len() != 2 {
        debug!("l_U_secondary got instance length {:?} != 2", self.l_u_secondary.X.len(),);
        return Err(SuperNovaError::NovaError(NovaError::ProofVerifyError));
      }

      if self.r_U_secondary.X.len() != 2 {
        debug!("r_U_secondary got instance length {:?} != 2", self.r_U_secondary.X.len(),);
        return Err(SuperNovaError::NovaError(NovaError::ProofVerifyError));
      }
    }

    let hash_primary = {
      let num_absorbs = num_ro_inputs(
        self.num_augmented_circuits,
        pp.augmented_circuit_params_primary.get_n_limbs(),
        pp[circuit_index].F_arity,
        true, // is_primary
      );

      let mut hasher = <Dual<E1> as Engine>::RO::new(pp.ro_consts_secondary.clone(), num_absorbs);
      hasher.absorb(self.pp_digest);
      hasher.absorb(E1::Scalar::from(self.i as u64));
      hasher.absorb(self.program_counter);

      for e in z0_primary {
        hasher.absorb(*e);
      }
      for e in &self.zi_primary {
        hasher.absorb(*e);
      }

      self.r_U_secondary.absorb_in_ro(&mut hasher);
      hasher.squeeze(NUM_HASH_BITS)
    };

    let hash_secondary = {
      let num_absorbs = num_ro_inputs(
        self.num_augmented_circuits,
        pp.augmented_circuit_params_secondary.get_n_limbs(),
        pp.circuit_shape_secondary.F_arity,
        false, // is_primary
      );
      let mut hasher = <E1 as Engine>::RO::new(pp.ro_consts_primary.clone(), num_absorbs);
      hasher.absorb(scalar_as_base::<E1>(self.pp_digest));
      hasher.absorb(<Dual<E1> as Engine>::Scalar::from(self.i as u64));

      for e in z0_secondary {
        hasher.absorb(*e);
      }
      for e in &self.zi_secondary {
        hasher.absorb(*e);
      }

      self.r_U_primary.iter().enumerate().for_each(|(i, U)| {
        U.as_ref()
          .unwrap_or(&RelaxedR1CSInstance::default(&*pp.ck_primary, &pp[i].r1cs_shape))
          .absorb_in_ro(&mut hasher);
      });
      hasher.squeeze(NUM_HASH_BITS)
    };

    if hash_primary != self.l_u_secondary.X[0] {
      debug!(
        "hash_primary {:?} not equal l_u_secondary.X[0] {:?}",
        hash_primary, self.l_u_secondary.X[0]
      );
      return Err(SuperNovaError::NovaError(NovaError::ProofVerifyError));
    }
    if hash_secondary != scalar_as_base::<Dual<E1>>(self.l_u_secondary.X[1]) {
      debug!(
        "hash_secondary {:?} not equal l_u_secondary.X[1] {:?}",
        hash_secondary, self.l_u_secondary.X[1]
      );
      return Err(SuperNovaError::NovaError(NovaError::ProofVerifyError));
    }

    // check the satisfiability of all instance/witness pairs
    let (res_r_primary, (res_r_secondary, res_l_secondary)) = rayon::join(
      || {
        self.r_U_primary.par_iter().zip_eq(self.r_W_primary.par_iter()).enumerate().try_for_each(
          |(i, (u, w))| {
            if let (Some(u), Some(w)) = (u, w) {
              pp[i].r1cs_shape.is_sat_relaxed(&pp.ck_primary, u, w)?
            }
            Ok(())
          },
        )
      },
      || {
        rayon::join(
          || {
            pp.circuit_shape_secondary.r1cs_shape.is_sat_relaxed(
              &pp.ck_secondary,
              &self.r_U_secondary,
              &self.r_W_secondary,
            )
          },
          || {
            pp.circuit_shape_secondary.r1cs_shape.is_sat(
              &pp.ck_secondary,
              &self.l_u_secondary,
              &self.l_w_secondary,
            )
          },
        )
      },
    );

    res_r_primary.map_err(|err| match err {
      NovaError::UnSatIndex(i) => SuperNovaError::UnSatIndex("r_primary", i),
      e => SuperNovaError::NovaError(e),
    })?;
    res_r_secondary.map_err(|err| match err {
      NovaError::UnSatIndex(i) => SuperNovaError::UnSatIndex("r_secondary", i),
      e => SuperNovaError::NovaError(e),
    })?;
    res_l_secondary.map_err(|err| match err {
      NovaError::UnSatIndex(i) => SuperNovaError::UnSatIndex("l_secondary", i),
      e => SuperNovaError::NovaError(e),
    })?;

    Ok((self.zi_primary.clone(), self.zi_secondary.clone()))
  }
}

/// SuperNova helper trait, for implementors that provide sets of sub-circuits
/// to be proved via NIVC. `C1` must be a type (likely an `Enum`) for which a
/// potentially-distinct instance can be supplied for each `index` below
/// `self.num_circuits()`.
pub trait NonUniformCircuit<E1>
where E1: CurveCycleEquipped {
  /// The type of the step-circuits on the primary
  type C1: StepCircuit<E1::Scalar>;
  /// The type of the step-circuits on the secondary
  type C2: StepCircuit<<Dual<E1> as Engine>::Scalar>;

  /// Initial circuit index, defaults to zero.
  fn initial_circuit_index(&self) -> usize { 0 }

  /// How many circuits are provided?
  fn num_circuits(&self) -> usize;

  /// Return a new instance of the primary circuit at `index`.
  fn primary_circuit(&self, circuit_index: usize) -> Self::C1;

  /// Return a new instance of the secondary circuit.
  fn secondary_circuit(&self) -> Self::C2;
}

/// Compute the circuit digest of a supernova [`StepCircuit`].
///
/// Note for callers: This function should be called with its performance
/// characteristics in mind. It will synthesize and digest the full `circuit`
/// given.
pub fn circuit_digest<E1: CurveCycleEquipped, C: StepCircuit<E1::Scalar>>(
  circuit: &C,
  num_augmented_circuits: usize,
) -> E1::Scalar {
  let augmented_circuit_params =
    SuperNovaAugmentedCircuitParams::new(BN_LIMB_WIDTH, BN_N_LIMBS, true);

  // ro_consts_circuit are parameterized by E2 because the type alias uses
  // E2::Base = E1::Scalar
  let ro_consts_circuit = ROConstantsCircuit::<Dual<E1>>::default();

  // Initialize ck for the primary
  let augmented_circuit: SuperNovaAugmentedCircuit<'_, Dual<E1>, C> =
    SuperNovaAugmentedCircuit::new(
      &augmented_circuit_params,
      None,
      circuit,
      ro_consts_circuit,
      num_augmented_circuits,
    );
  let mut cs: ShapeCS<E1> = ShapeCS::new();
  let _ = augmented_circuit.synthesize(&mut cs);

  let F_arity = circuit.arity();
  let circuit_params = R1CSWithArity::new(cs.r1cs_shape(), F_arity);
  circuit_params.digest()
}

/// Compute the number of absorbs for the random-oracle computing the circuit
/// output X = H(vk, i, pc, z0, zi, U)
fn num_ro_inputs(num_circuits: usize, num_limbs: usize, arity: usize, is_primary: bool) -> usize {
  let num_circuits = if is_primary { 1 } else { num_circuits };

  // [W(x,y,∞), E(x,y,∞), u] + [X0, X1] * #num_limb
  let instance_size = 3 + 3 + 1 + 2 * num_limbs;

  2 // params, i
    + usize::from(is_primary) // optional program counter
      + 2 * arity // z0, zi
      + num_circuits * instance_size
}

pub mod error;
pub mod snark;
mod utils;

#[cfg(test)] mod test;
