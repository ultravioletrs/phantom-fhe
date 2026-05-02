fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", phantom_examples::mpbgv_basic()?);
    Ok(())
}
