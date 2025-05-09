//! There are two augmented circuits: the primary and the secondary.
//! Each of them is over a curve in a 2-cycle of elliptic curves.
//! We have two running instances. Each circuit takes as input 2 hashes: one for
//! each of the running instances. Each of these hashes is H(params = H(shape,
//! ck), i, z0, zi, U). Each circuit folds the last invocation of the other into
//! the running instance

use bellpepper::gadgets::{boolean_utils::conditionally_select_slice, Assignment};
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use ff::Field;
use serde::{Deserialize, Serialize};

use crate::{
  constants::{NIO_NOVA_FOLD, NUM_FE_WITHOUT_IO_FOR_CRHF, NUM_HASH_BITS},
  gadgets::{
    alloc_num_equals, alloc_scalar_as_base, alloc_zero, le_bits_to_num, AllocatedPoint,
    AllocatedR1CSInstance, AllocatedRelaxedR1CSInstance,
  },
  r1cs::{R1CSInstance, RelaxedR1CSInstance},
  supernova::StepCircuit,
  traits::{commitment::CommitmentTrait, Engine, ROCircuitTrait, ROConstantsCircuit},
  Commitment,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NovaAugmentedCircuitParams {
  limb_width:         usize,
  n_limbs:            usize,
  is_primary_circuit: bool, // A boolean indicating if this is the primary circuit
}

impl NovaAugmentedCircuitParams {
  pub const fn new(limb_width: usize, n_limbs: usize, is_primary_circuit: bool) -> Self {
    Self { limb_width, n_limbs, is_primary_circuit }
  }
}

// NOTES: All these options here seem to point towards using a typestate pattern
// or something.

#[derive(Debug, Serialize)]
#[serde(bound = "")]
pub struct NovaAugmentedCircuitInputs<E: Engine> {
  params: E::Scalar,
  i:      E::Base,
  z0:     Vec<E::Base>,
  zi:     Option<Vec<E::Base>>,
  U:      Option<RelaxedR1CSInstance<E>>,
  u:      Option<R1CSInstance<E>>,
  T:      Option<Commitment<E>>,
}

impl<E: Engine> NovaAugmentedCircuitInputs<E> {
  /// Create new inputs/witness for the verification circuit
  pub fn new(
    params: E::Scalar,
    i: E::Base,
    z0: Vec<E::Base>,
    zi: Option<Vec<E::Base>>,
    U: Option<RelaxedR1CSInstance<E>>,
    u: Option<R1CSInstance<E>>,
    T: Option<Commitment<E>>,
  ) -> Self {
    Self { params, i, z0, zi, U, u, T }
  }
}

/// The augmented circuit F' in Nova that includes a step circuit F
/// and the circuit for the verifier in Nova's non-interactive folding scheme
pub struct NovaAugmentedCircuit<'a, E: Engine, SC: StepCircuit<E::Base>> {
  params:       &'a NovaAugmentedCircuitParams,
  ro_consts:    ROConstantsCircuit<E>,
  inputs:       Option<NovaAugmentedCircuitInputs<E>>,
  step_circuit: &'a SC, // The function that is applied for each step
}

impl<'a, E: Engine, SC: StepCircuit<E::Base>> NovaAugmentedCircuit<'a, E, SC> {
  /// Create a new verification circuit for the input relaxed r1cs instances
  pub const fn new(
    params: &'a NovaAugmentedCircuitParams,
    inputs: Option<NovaAugmentedCircuitInputs<E>>,
    step_circuit: &'a SC,
    ro_consts: ROConstantsCircuit<E>,
  ) -> Self {
    Self { params, inputs, step_circuit, ro_consts }
  }

  /// Allocate all witnesses and return
  fn alloc_witness<CS: ConstraintSystem<<E as Engine>::Base>>(
    &self,
    mut cs: CS,
    arity: usize,
  ) -> Result<
    (
      AllocatedNum<E::Base>,
      AllocatedNum<E::Base>,
      Vec<AllocatedNum<E::Base>>,
      Vec<AllocatedNum<E::Base>>,
      AllocatedRelaxedR1CSInstance<E, NIO_NOVA_FOLD>,
      AllocatedR1CSInstance<E, NIO_NOVA_FOLD>,
      AllocatedPoint<E::GE>,
    ),
    SynthesisError,
  > {
    // Allocate the params
    let params = alloc_scalar_as_base::<E, _>(
      cs.namespace(|| "params"),
      self.inputs.as_ref().map(|inputs| inputs.params),
    )?;

    // Allocate i
    let i = AllocatedNum::alloc(cs.namespace(|| "i"), || Ok(self.inputs.get()?.i))?;

    // Allocate z0
    let z_0 = (0..arity)
      .map(|i| {
        AllocatedNum::alloc(cs.namespace(|| format!("z0_{i}")), || Ok(self.inputs.get()?.z0[i]))
      })
      .collect::<Result<Vec<AllocatedNum<E::Base>>, _>>()?;

    // Allocate zi. If inputs.zi is not provided (base case) allocate default value
    // 0
    let zero = vec![E::Base::ZERO; arity];
    let z_i = (0..arity)
      .map(|i| {
        AllocatedNum::alloc(cs.namespace(|| format!("zi_{i}")), || {
          Ok(self.inputs.get()?.zi.as_ref().unwrap_or(&zero)[i])
        })
      })
      .collect::<Result<Vec<AllocatedNum<E::Base>>, _>>()?;

    // Allocate the running instance
    let U: AllocatedRelaxedR1CSInstance<E, NIO_NOVA_FOLD> = AllocatedRelaxedR1CSInstance::alloc(
      cs.namespace(|| "Allocate U"),
      self.inputs.as_ref().and_then(|inputs| inputs.U.as_ref()),
      self.params.limb_width,
      self.params.n_limbs,
    )?;

    // Allocate the instance to be folded in
    let u = AllocatedR1CSInstance::alloc(
      cs.namespace(|| "allocate instance u to fold"),
      self.inputs.as_ref().and_then(|inputs| inputs.u.as_ref()),
    )?;

    // Allocate T
    let T = AllocatedPoint::alloc(
      cs.namespace(|| "allocate T"),
      self.inputs.as_ref().and_then(|inputs| inputs.T.map(|T| T.to_coordinates())),
    )?;
    T.check_on_curve(cs.namespace(|| "check T on curve"))?;

    Ok((params, i, z_0, z_i, U, u, T))
  }

  /// Synthesizes base case and returns the new relaxed `R1CSInstance`
  fn synthesize_base_case<CS: ConstraintSystem<<E as Engine>::Base>>(
    &self,
    mut cs: CS,
    u: AllocatedR1CSInstance<E, NIO_NOVA_FOLD>,
  ) -> Result<AllocatedRelaxedR1CSInstance<E, NIO_NOVA_FOLD>, SynthesisError> {
    let U_default: AllocatedRelaxedR1CSInstance<E, NIO_NOVA_FOLD> =
      if self.params.is_primary_circuit {
        // The primary circuit just returns the default R1CS instance
        AllocatedRelaxedR1CSInstance::default(
          cs.namespace(|| "Allocate U_default"),
          self.params.limb_width,
          self.params.n_limbs,
        )?
      } else {
        // The secondary circuit returns the incoming R1CS instance
        AllocatedRelaxedR1CSInstance::from_r1cs_instance(
          cs.namespace(|| "Allocate U_default"),
          u,
          self.params.limb_width,
          self.params.n_limbs,
        )?
      };
    Ok(U_default)
  }

  /// Synthesizes non base case and returns the new relaxed `R1CSInstance`
  /// And a boolean indicating if all checks pass
  fn synthesize_non_base_case<CS: ConstraintSystem<<E as Engine>::Base>>(
    &self,
    mut cs: CS,
    params: &AllocatedNum<E::Base>,
    i: &AllocatedNum<E::Base>,
    z_0: &[AllocatedNum<E::Base>],
    z_i: &[AllocatedNum<E::Base>],
    U: &AllocatedRelaxedR1CSInstance<E, NIO_NOVA_FOLD>,
    u: &AllocatedR1CSInstance<E, NIO_NOVA_FOLD>,
    T: &AllocatedPoint<E::GE>,
    arity: usize,
  ) -> Result<(AllocatedRelaxedR1CSInstance<E, NIO_NOVA_FOLD>, AllocatedBit), SynthesisError> {
    // Check that u.x[0] = Hash(params, U, i, z0, zi)
    let mut ro = E::ROCircuit::new(self.ro_consts.clone(), NUM_FE_WITHOUT_IO_FOR_CRHF + 2 * arity);
    ro.absorb(params);
    ro.absorb(i);
    for e in z_0 {
      ro.absorb(e);
    }
    for e in z_i {
      ro.absorb(e);
    }
    U.absorb_in_ro(cs.namespace(|| "absorb U"), &mut ro)?;

    let hash_bits = ro.squeeze(cs.namespace(|| "Input hash"), NUM_HASH_BITS)?;
    let hash = le_bits_to_num(cs.namespace(|| "bits to hash"), &hash_bits)?;
    let check_pass = alloc_num_equals(
      cs.namespace(|| "check consistency of u.X[0] with H(params, U, i, z0, zi)"),
      &u.X[0],
      &hash,
    )?;

    // Run NIFS Verifier
    let U_fold = U.fold_with_r1cs(
      cs.namespace(|| "compute fold of U and u"),
      params,
      u,
      T,
      self.ro_consts.clone(),
      self.params.limb_width,
      self.params.n_limbs,
    )?;

    Ok((U_fold, check_pass))
  }
}

impl<E: Engine, SC: StepCircuit<E::Base>> NovaAugmentedCircuit<'_, E, SC> {
  /// synthesize circuit giving constraint system
  pub fn synthesize<CS: ConstraintSystem<<E as Engine>::Base>>(
    self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Base>>, SynthesisError> {
    let arity = self.step_circuit.arity();

    // Allocate all witnesses
    let (params, i, z_0, z_i, U, u, T) =
      self.alloc_witness(cs.namespace(|| "allocate the circuit witness"), arity)?;

    // Compute variable indicating if this is the base case
    let zero = alloc_zero(cs.namespace(|| "zero"));
    let is_base_case = alloc_num_equals(cs.namespace(|| "Check if base case"), &i.clone(), &zero)?;

    // Synthesize the circuit for the base case and get the new running instance
    let Unew_base = self.synthesize_base_case(cs.namespace(|| "base case"), u.clone())?;

    // Synthesize the circuit for the non-base case and get the new running
    // instance along with a boolean indicating if all checks have passed
    let (Unew_non_base, check_non_base_pass) = self.synthesize_non_base_case(
      cs.namespace(|| "synthesize non base case"),
      &params,
      &i,
      &z_0,
      &z_i,
      &U,
      &u,
      &T,
      arity,
    )?;

    // Either check_non_base_pass=true or we are in the base case
    let should_be_false = AllocatedBit::nor(
      cs.namespace(|| "check_non_base_pass nor base_case"),
      &check_non_base_pass,
      &is_base_case,
    )?;
    cs.enforce(
      || "check_non_base_pass nor base_case = false",
      |lc| lc + should_be_false.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc,
    );

    // Compute the U_new
    let Unew = Unew_base.conditionally_select(
      cs.namespace(|| "compute U_new"),
      &Unew_non_base,
      &Boolean::from(is_base_case.clone()),
    )?;

    // Compute i + 1
    let i_new =
      AllocatedNum::alloc(cs.namespace(|| "i + 1"), || Ok(*i.get_value().get()? + E::Base::ONE))?;
    cs.enforce(
      || "check i + 1",
      |lc| lc,
      |lc| lc,
      |lc| lc + i_new.get_variable() - CS::one() - i.get_variable(),
    );

    // Compute z_{i+1}
    let z_input = conditionally_select_slice(
      cs.namespace(|| "select input to F"),
      &z_0,
      &z_i,
      &Boolean::from(is_base_case),
    )?;

    // TODO: Note, I changed this here because I removed the other `StepCircuit`
    // trait.
    let (_pc, z_next) = self.step_circuit.synthesize(&mut cs.namespace(|| "F"), None, &z_input)?;

    if z_next.len() != arity {
      return Err(SynthesisError::IncompatibleLengthVector("z_next".to_string()));
    }

    // Compute the new hash H(params, Unew, i+1, z0, z_{i+1})
    let mut ro = E::ROCircuit::new(self.ro_consts, NUM_FE_WITHOUT_IO_FOR_CRHF + 2 * arity);
    ro.absorb(&params);
    ro.absorb(&i_new);
    for e in &z_0 {
      ro.absorb(e);
    }
    for e in &z_next {
      ro.absorb(e);
    }
    Unew.absorb_in_ro(cs.namespace(|| "absorb U_new"), &mut ro)?;
    let hash_bits = ro.squeeze(cs.namespace(|| "output hash bits"), NUM_HASH_BITS)?;
    let hash = le_bits_to_num(cs.namespace(|| "convert hash to num"), &hash_bits)?;

    // Outputs the computed hash and u.X[1] that corresponds to the hash of the
    // other circuit
    u.X[1].inputize(cs.namespace(|| "Output unmodified hash of the other circuit"))?;
    hash.inputize(cs.namespace(|| "output new hash of this circuit"))?;

    Ok(z_next)
  }
}

// #[cfg(test)]
// mod tests {
//     use expect_test::{expect, Expect};

//     use super::*;
//     use crate::{
//         bellpepper::{
//             r1cs::{NovaShape, NovaWitness},
//             solver::SatisfyingAssignment,
//             test_shape_cs::TestShapeCS,
//         },
//         constants::{BN_LIMB_WIDTH, BN_N_LIMBS},
//         gadgets::scalar_as_base,
//         provider::{
//             poseidon::PoseidonConstantsCircuit, Bn256EngineKZG,
// GrumpkinEngine, PallasEngine,             Secp256k1Engine, Secq256k1Engine,
// VestaEngine,         },
//         traits::{snark::default_ck_hint, CurveCycleEquipped, Dual},
//     };

//     // In the following we use 1 to refer to the primary, and 2 to refer to
// the     // secondary circuit
//     fn test_recursive_circuit_with<E1>(
//         primary_params: &NovaAugmentedCircuitParams,
//         secondary_params: &NovaAugmentedCircuitParams,
//         ro_consts1: ROConstantsCircuit<Dual<E1>>,
//         ro_consts2: ROConstantsCircuit<E1>,
//         expected_num_constraints_primary: &Expect,
//         expected_num_constraints_secondary: &Expect,
//     ) where
//         E1: CurveCycleEquipped,
//     {
//         let tc1 = TrivialCircuit::default();
//         // Initialize the shape and ck for the primary
//         let circuit1: NovaAugmentedCircuit<
//             '_,
//             Dual<E1>,
//             TrivialCircuit<<Dual<E1> as Engine>::Base>,
//         > = NovaAugmentedCircuit::new(primary_params, None, &tc1,
//         > ro_consts1.clone());
//         let mut cs: TestShapeCS<E1> = TestShapeCS::new();
//         let _ = circuit1.synthesize(&mut cs);
//         let (shape1, ck1) = cs.r1cs_shape_and_key(&*default_ck_hint());

//         expected_num_constraints_primary.assert_eq(&cs.num_constraints().
// to_string());

//         let tc2 = TrivialCircuit::default();
//         // Initialize the shape and ck for the secondary
//         let circuit2: NovaAugmentedCircuit<'_, E1, TrivialCircuit<<E1 as
// Engine>::Base>> =             NovaAugmentedCircuit::new(secondary_params,
// None, &tc2, ro_consts2.clone());         let mut cs: TestShapeCS<Dual<E1>> =
// TestShapeCS::new();         let _ = circuit2.synthesize(&mut cs);
//         let (shape2, ck2) = cs.r1cs_shape_and_key(&*default_ck_hint());

//         expected_num_constraints_secondary.assert_eq(&cs.num_constraints().
// to_string());

//         // Execute the base case for the primary
//         let zero1 = <<Dual<E1> as Engine>::Base as Field>::ZERO;
//         let mut cs1 = SatisfyingAssignment::<E1>::new();
//         let inputs1: NovaAugmentedCircuitInputs<Dual<E1>> =
// NovaAugmentedCircuitInputs::new(             scalar_as_base::<E1>(zero1), //
// pass zero for testing             zero1,
//             vec![zero1],
//             None,
//             None,
//             None,
//             None,
//         );
//         let circuit1: NovaAugmentedCircuit<
//             '_,
//             Dual<E1>,
//             TrivialCircuit<<Dual<E1> as Engine>::Base>,
//         > = NovaAugmentedCircuit::new(primary_params, Some(inputs1), &tc1,
//         > ro_consts1);
//         let _ = circuit1.synthesize(&mut cs1);
//         let (inst1, witness1) = cs1.r1cs_instance_and_witness(&shape1,
// &ck1).unwrap();         // Make sure that this is satisfiable
//         shape1.is_sat(&ck1, &inst1, &witness1).unwrap();

//         // Execute the base case for the secondary
//         let zero2 = <<E1 as Engine>::Base as Field>::ZERO;
//         let mut cs2 = SatisfyingAssignment::<Dual<E1>>::new();
//         let inputs2: NovaAugmentedCircuitInputs<E1> =
// NovaAugmentedCircuitInputs::new(
// scalar_as_base::<Dual<E1>>(zero2), // pass zero for testing
// zero2,             vec![zero2],
//             None,
//             None,
//             Some(inst1),
//             None,
//         );
//         let circuit2: NovaAugmentedCircuit<'_, E1, TrivialCircuit<<E1 as
// Engine>::Base>> =             NovaAugmentedCircuit::new(secondary_params,
// Some(inputs2), &tc2, ro_consts2);         let _ = circuit2.synthesize(&mut
// cs2);         let (inst2, witness2) = cs2.r1cs_instance_and_witness(&shape2,
// &ck2).unwrap();         // Make sure that it is satisfiable
//         shape2.is_sat(&ck2, &inst2, &witness2).unwrap();
//     }

//     #[test]
//     fn test_recursive_circuit_pasta() {
//         // this test checks against values that must be replicated in
// benchmarks if         // changed here
//         let params1 = NovaAugmentedCircuitParams::new(BN_LIMB_WIDTH,
// BN_N_LIMBS, true);         let params2 =
// NovaAugmentedCircuitParams::new(BN_LIMB_WIDTH, BN_N_LIMBS, false);
//         let ro_consts1: ROConstantsCircuit<VestaEngine> =
// PoseidonConstantsCircuit::default();         let ro_consts2:
// ROConstantsCircuit<PallasEngine> = PoseidonConstantsCircuit::default();

//         test_recursive_circuit_with::<PallasEngine>(
//             &params1,
//             &params2,
//             ro_consts1,
//             ro_consts2,
//             &expect!["9817"],
//             &expect!["10349"],
//         );
//     }

//     #[test]
//     fn test_recursive_circuit_bn256_grumpkin() {
//         let params1 = NovaAugmentedCircuitParams::new(BN_LIMB_WIDTH,
// BN_N_LIMBS, true);         let params2 =
// NovaAugmentedCircuitParams::new(BN_LIMB_WIDTH, BN_N_LIMBS, false);
//         let ro_consts1: ROConstantsCircuit<GrumpkinEngine> =
// PoseidonConstantsCircuit::default();         let ro_consts2:
// ROConstantsCircuit<Bn256EngineKZG> = PoseidonConstantsCircuit::default();

//         test_recursive_circuit_with::<Bn256EngineKZG>(
//             &params1,
//             &params2,
//             ro_consts1,
//             ro_consts2,
//             &expect!["9985"],
//             &expect!["10538"],
//         );
//     }

//     #[test]
//     fn test_recursive_circuit_secpq() {
//         let params1 = NovaAugmentedCircuitParams::new(BN_LIMB_WIDTH,
// BN_N_LIMBS, true);         let params2 =
// NovaAugmentedCircuitParams::new(BN_LIMB_WIDTH, BN_N_LIMBS, false);
//         let ro_consts1: ROConstantsCircuit<Secq256k1Engine> =
// PoseidonConstantsCircuit::default();         let ro_consts2:
// ROConstantsCircuit<Secp256k1Engine> = PoseidonConstantsCircuit::default();

//         test_recursive_circuit_with::<Secp256k1Engine>(
//             &params1,
//             &params2,
//             ro_consts1,
//             ro_consts2,
//             &expect!["10264"],
//             &expect!["10961"],
//         );
//     }
// }
