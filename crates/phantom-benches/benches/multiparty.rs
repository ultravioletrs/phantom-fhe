use phantom_benches::{print_result, time_iterations};

fn main() {
    let iterations = 20;
    let elapsed = time_iterations(
        || {
            let _ = phantom_examples::mpckks_interactive_bootstrap().unwrap();
        },
        iterations,
    );
    print_result("multiparty", iterations, elapsed);
}
