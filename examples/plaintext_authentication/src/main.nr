use nivc::FoldingVariables;
use noir_web_prover_circuits::chacha20::{NivcState}

global PUBLIC_IO_VARS: u8 = 11;

fn main(
    folding_variables: pub FoldingVariables<PUBLIC_IO_VARS>,
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    plaintext: [u8; DATA_BYTES],
    ciphertext_digest: Field,
) -> pub FoldingVariables<PUBLIC_IO_VARS> {
    let nivc = NivcState { key, nonce, counter, plaintext, ciphertext_digest };
    let step_out: [Field; PUBLIC_IO_VARS] = nivc.verify();

    step_out
}

fn state_to_folding_vars(
    state: [Field; PUBLIC_IO_VARS]
) -> FoldingVariables<PUBLIC_IO_VARS> {
    FoldingVariables {
        registers: [
            folding_variables.registers[0],
            folding_variables.registers[1],
            folding_variables.registers[2],
            folding_variables.registers[3],
            folding_variables.registers[4],
            folding_variables.registers[5],
            folding_variables.registers[6],
            folding_variables.registers[7],
            folding_variables.registers[8],
            folding_variables.registers[9],
            folding_variables.registers[10],
        ],
    }
}

#[test]
fn test_main() {
    main(1, 2);
}
