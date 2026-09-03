//! `pass gen` — generate a password or passphrase.

use anyhow::{Context, Result};
use colored::*;
use passlib::generator::{entropy_bits, generate_password, GeneratorOptions};

#[allow(clippy::too_many_arguments)]
pub fn cmd_gen(
    length: usize,
    no_symbols: bool,
    no_digits: bool,
    no_uppercase: bool,
    allow_ambiguous: bool,
    passphrase: bool,
    separator: String,
    count: usize,
) -> Result<()> {
    let options = GeneratorOptions {
        length,
        lowercase: true,
        uppercase: !no_uppercase,
        digits: !no_digits,
        symbols: !no_symbols,
        allow_ambiguous,
        passphrase,
        separator,
    };

    let bits = entropy_bits(&options);

    for _ in 0..count.max(1) {
        let password = generate_password(&options).context("Failed to generate a password")?;
        // Bare on stdout so `pass gen | wl-copy` works; the commentary goes
        // to stderr where a pipe won't pick it up.
        println!("{}", password.as_str());
    }

    eprintln!("{}", format!("≈{bits:.0} bits of entropy{}", strength_note(bits)).bright_black());

    Ok(())
}

fn strength_note(bits: f64) -> &'static str {
    // Rough, deliberately conservative bands: below 60 bits is within reach
    // of a determined offline attack against a fast hash, above 100 is not.
    if bits < 60.0 {
        " — weak, raise the length"
    } else if bits < 100.0 {
        " — fine for a site password"
    } else {
        " — strong"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_bands_are_ordered() {
        assert!(strength_note(40.0).contains("weak"));
        assert!(strength_note(80.0).contains("fine"));
        assert!(strength_note(128.0).contains("strong"));
    }

    #[test]
    fn flags_map_onto_generator_options() {
        // `--no-symbols` etc. are negative flags on the CLI but positive
        // fields in the library; getting the inversion wrong would silently
        // produce weaker passwords than asked for.
        let options = GeneratorOptions {
            length: 20,
            lowercase: true,
            uppercase: !true,
            digits: !true,
            symbols: !true,
            allow_ambiguous: false,
            passphrase: false,
            separator: "-".to_string(),
        };
        let generated = generate_password(&options).unwrap();
        assert!(generated.chars().all(|c| c.is_ascii_lowercase()));
    }
}
