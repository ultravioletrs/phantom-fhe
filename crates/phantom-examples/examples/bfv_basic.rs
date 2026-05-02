fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", phantom_examples::bfv_basic()?);
    Ok(())
}
