use anyhow::Result;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;
// use std::collections::HashSet;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use bloom::{BloomFilter, ASMS};
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;
use std::fmt::Debug;

// Function to convert a string to field elements
fn string_to_field_elements<F: Field>(s: &str) -> Vec<F> {
    s.bytes().map(|b| F::from_canonical_u32(b as u32)).collect()
}

/// Bloom filter-based Zero-knowledge proof to determine if list1 contains elements from list2.
fn main() -> Result<()> {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // Two lists of strings to be compared
    let list1 = vec![
        "plonky2_example", "zero_knowledge", "rust_programming", "zk_snarks",
        "plonk_proof", "hash_functions", "cryptography", "merkle_tree",
        "circuit_builder", "poseidon_hash"
    ];
    
    let list2 = vec![
        "example", "proof", "zk", "snarks", "hash", "tree", 
        "builder", "rust", "zero", "functions", "cryptography", "merkle_tree",
    ];

    // Initialize the Bloom filter with an appropriate size
    let bloom_size = list1.iter().map(|s| s.len()).sum::<usize>();
    let mut bloom = BloomFilter::with_rate(0.01, bloom_size as u32);

    // Convert strings in list1 to field elements and add them to the Bloom filter
    for string1 in &list1 {
        let str1_elements = string_to_field_elements::<F>(string1);
        let substring: Vec<u8> = str1_elements
            .iter()
            .map(|&elem| elem.to_canonical_u64() as u8)
            .collect();
        bloom.insert(&substring);
    }

    let mut config = CircuitConfig::standard_recursion_config();
    config.zero_knowledge = true;  // Enable zero-knowledge mode
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Iterate through list2 to check membership in Bloom filter
    for string2 in &list2 {
        let str2_elements = string_to_field_elements::<F>(string2);

        // Convert the string2 to a Vec<u8> for comparison.
        let str2_bytes: Vec<u8> = str2_elements
            .iter()
            .map(|&elem| elem.to_canonical_u64() as u8)
            .collect();

        // Check if string2 is likely contained in any string of list1 using the Bloom filter.
        let mut contains_flag = builder._false(); // Start with false as a BoolTarget.

        if bloom.contains(&str2_bytes) {
            contains_flag = builder._true();
        }

        // Create constants for F::ONE and F::ZERO outside the select call.
        let one = builder.constant(F::ONE);
        let zero = builder.constant(F::ZERO);

        // Manually convert BoolTarget to a Target.
        let contains_flag_target = builder.select(contains_flag, one, zero);
        
        // Public output: whether list1 likely contains the string from list2.
        builder.register_public_input(contains_flag_target);
    }

    let data = builder.build::<C>();

    // Set witness values for the string1 and string2 targets.
    let pw = PartialWitness::new();
    // Note: You can fill in the witness logic as needed.

    let proof = data.prove(pw)?;

    // Output result for each string in list2.
    for (i, string2) in list2.iter().enumerate() {
        let result = proof.public_inputs.get(i).unwrap();
        println!(
            "Does list1 likely contain '{}'? {}",
            string2,
            if *result == F::ONE { "Yes" } else { "No" }
        );
    }

    data.verify(proof)?;

    // Access and print circuit statistics
    print_common_data(&data.common);

    Ok(())
}

fn print_common_data<F: Debug + RichField + Extendable<D>, const D: usize>(common_data: &CommonCircuitData<F, D>) {
    println!("{:?}", common_data);
}