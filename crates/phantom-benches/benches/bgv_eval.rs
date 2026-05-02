use phantom_benches::{print_result, time_iterations};

fn main() {
    let iterations = 20;
    let elapsed = time_iterations(
        || {
            let _ = phantom_examples::bgv_polynomial().unwrap();
        },
        iterations,
    );
    print_result("bgv_eval", iterations, elapsed);
}
