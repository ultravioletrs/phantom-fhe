use phantom_benches::{print_result, time_iterations};

fn main() {
    let iterations = 20;
    let elapsed = time_iterations(
        || {
            let _ = phantom_examples::bfv_rotation().unwrap();
        },
        iterations,
    );
    print_result("bfv_eval", iterations, elapsed);
}
