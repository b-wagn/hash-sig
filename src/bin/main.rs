use std::time::Instant;

use hashsig::signature::{
    SignatureScheme,
    generalized_xmss::instantiations_poseidon::{
        lifetime_2_to_the_18::{
            target_sum::{
                SIGTargetSumLifetime18W1NoOff, SIGTargetSumLifetime18W2NoOff,
                SIGTargetSumLifetime18W4NoOff, SIGTargetSumLifetime18W8NoOff,
            },
            winternitz::{
                SIGWinternitzLifetime18W1, SIGWinternitzLifetime18W2, SIGWinternitzLifetime18W4,
                SIGWinternitzLifetime18W8,
            },
        },
        lifetime_2_to_the_20::{
            target_sum::{
                SIGTargetSumLifetime20W1NoOff, SIGTargetSumLifetime20W2NoOff,
                SIGTargetSumLifetime20W4NoOff, SIGTargetSumLifetime20W8NoOff,
            },
            winternitz::{
                SIGWinternitzLifetime20W1, SIGWinternitzLifetime20W2, SIGWinternitzLifetime20W4,
                SIGWinternitzLifetime20W8,
            },
        },
    },
};
use rand::{Rng, rngs::ThreadRng};

// Function to measure execution time
fn measure_time<T: SignatureScheme, R: Rng>(description: &str, rng: &mut R) {
    // key gen

    let start = Instant::now();
    let (_pk, _sk) = T::key_gen(rng, 0, T::LIFETIME as usize);
    let duration = start.elapsed();
    println!("{description} - Gen: {duration:?}");
}

// Main function to run the program
fn main() {
    let mut rng = rand::rng();

    // Lifetime 2^18 - Winternitz
    measure_time::<SIGWinternitzLifetime18W1, ThreadRng>(
        "Poseidon - L 18 - Winternitz - w 1",
        &mut rng,
    );
    measure_time::<SIGWinternitzLifetime18W2, ThreadRng>(
        "Poseidon - L 18 - Winternitz - w 2",
        &mut rng,
    );
    measure_time::<SIGWinternitzLifetime18W4, ThreadRng>(
        "Poseidon - L 18 - Winternitz - w 4",
        &mut rng,
    );
    measure_time::<SIGWinternitzLifetime18W8, ThreadRng>(
        "Poseidon - L 18 - Winternitz - w 8",
        &mut rng,
    );

    // Lifetime 2^18 - Target Sum
    measure_time::<SIGTargetSumLifetime18W1NoOff, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 1",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime18W2NoOff, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 2",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime18W4NoOff, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 4",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime18W8NoOff, ThreadRng>(
        "Poseidon - L 18 - Target Sum - w 8",
        &mut rng,
    );

    // Lifetime 2^20 - Winternitz
    measure_time::<SIGWinternitzLifetime20W1, ThreadRng>(
        "Poseidon - L 20 - Winternitz - w 1",
        &mut rng,
    );
    measure_time::<SIGWinternitzLifetime20W2, ThreadRng>(
        "Poseidon - L 20 - Winternitz - w 2",
        &mut rng,
    );
    measure_time::<SIGWinternitzLifetime20W4, ThreadRng>(
        "Poseidon - L 20 - Winternitz - w 4",
        &mut rng,
    );
    measure_time::<SIGWinternitzLifetime20W8, ThreadRng>(
        "Poseidon - L 20 - Winternitz - w 8",
        &mut rng,
    );

    // Lifetime 2^20 - Target Sum
    measure_time::<SIGTargetSumLifetime20W1NoOff, ThreadRng>(
        "Poseidon - L 20- Target Sum - w 1",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime20W2NoOff, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 2",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime20W4NoOff, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 4",
        &mut rng,
    );
    measure_time::<SIGTargetSumLifetime20W8NoOff, ThreadRng>(
        "Poseidon - L 20 - Target Sum - w 8",
        &mut rng,
    );
}
