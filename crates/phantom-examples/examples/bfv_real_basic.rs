fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", phantom_examples::bfv_real_basic()?);
    Ok(())
}
