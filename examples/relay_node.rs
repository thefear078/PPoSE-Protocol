//! Example relay node stub — Phase 2 will wire UDP + routing.

fn main() {
    println!(
        "PPoSE relay_node scaffold — max hops {}",
        ppose::DEFAULT_MAX_HOPS
    );
    println!("internal MTU {}", ppose::INTERNAL_MTU);
}
