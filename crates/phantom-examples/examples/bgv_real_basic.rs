fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", phantom_examples::bgv_real_basic()?);
    Ok(())
}
