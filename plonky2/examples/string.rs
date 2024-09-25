use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

/// Convert string into vector of field elements (e.g., based on ASCII values).
fn string_to_field_elements<F: Field>(s: &str) -> Vec<F> {
    s.bytes().map(|b| F::from_canonical_u32(b as u32)).collect()
}

/// Zero-knowledge proof to determine if `String 1` contains `String 2`.
fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Strings to be compared.
    let string1 = "plonky2_example";
    let string2 = "example1";

    // Convert both strings into vectors of field elements.
    let str1_elements = string_to_field_elements::<F>(string1);
    let str2_elements = string_to_field_elements::<F>(string2);

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create virtual targets for both strings.
    let str1_targets: Vec<_> = (0..str1_elements.len())
        .map(|_| builder.add_virtual_target())
        .collect();
    let str2_targets: Vec<_> = (0..str2_elements.len())
        .map(|_| builder.add_virtual_target())
        .collect();

    // Set string1 and string2 as public inputs (for demonstration purposes).
    for &target in &str1_targets {
        builder.register_public_input(target);
    }
    for &target in &str2_targets {
        builder.register_public_input(target);
    }

    // Iterate over all possible starting positions in string1.
    let mut contains_flag = builder._false(); // Start with false as a BoolTarget.
    for i in 0..=str1_elements.len() - str2_elements.len() {
        let mut match_flag = builder._true(); // Start with true as a BoolTarget.

        // Check if string2 matches at this starting position in string1.
        for (j, &target2) in str2_targets.iter().enumerate() {
            let target1 = str1_targets[i + j];
            // let is_equal = builder.is_equal(target1, target2);
            // match_flag = builder.and(match_flag, is_equal); // Logical AND to keep matching state.
            match_flag = builder.is_equal(target1, target2);

        // If a match is found, set contains_flag to true (OR logic).
        // contains_flag = builder.or(contains_flag, match_flag);
        }
        contains_flag = builder.or(contains_flag, match_flag);
    }

    // Create constants for F::ONE and F::ZERO outside the select call.
    let one = builder.constant(F::ONE);
    let zero = builder.constant(F::ZERO);

    // Manually convert BoolTarget to a Target.
    let contains_flag_target = builder.select(contains_flag, one, zero);
    
    // Public output: whether string1 contains string2.
    builder.register_public_intput(contains_flag_target);

    // Set witness values for the string1 and string2 targets.
    let mut pw = PartialWitness::new();
    for (target, &value) in str1_targets.iter().zip(&str1_elements) {
        pw.set_target(*target, value)?;
    }
    for (target, &value) in str2_targets.iter().zip(&str2_elements) {
        pw.set_target(*target, value)?;
    }

    let data = builder.build::<C>();
    let proof = data.prove(pw)?;

    // Output result: whether string1 contains string2.
    let result = proof.public_inputs.last().unwrap();
    println!(
        "Does '{}' contain '{}'? {}",
        string1,
        string2,
        if *result == F::ONE { "Yes" } else { "No" }
    );

    data.verify(proof)
}
