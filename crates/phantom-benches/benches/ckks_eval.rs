use phantom_benches::{print_result, time_iterations};

fn main() {
    let iterations = 20;
    let elapsed = time_iterations(
        || {
            let _ = phantom_examples::ckks_rescale().unwrap();
        },
        iterations,
    );
    print_result("ckks_eval", iterations, elapsed);
}
