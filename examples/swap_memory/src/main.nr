use nivc::FoldingVariables;

/// Swap the first two registers while preserving others.
pub fn main(folding_variables: pub FoldingVariables<11>, next_pc: Field) -> pub FoldingVariables<11> {
    FoldingVariables {
        registers: [
            folding_variables.registers[1],
            folding_variables.registers[0],
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
        program_counter: next_pc,
    }
}
