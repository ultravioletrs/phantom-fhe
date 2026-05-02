fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", phantom_examples::ckks_dft()?);
    Ok(())
}
