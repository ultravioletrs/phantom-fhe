fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", phantom_examples::mpckks_interactive_bootstrap()?);
    Ok(())
}
