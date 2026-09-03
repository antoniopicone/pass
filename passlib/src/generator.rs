//! Password generation.
//!
//! Two shapes, because they solve different problems: a random character
//! password for anything a machine will store, and a diceware-style
//! passphrase for the handful of secrets a human has to retype — the master
//! password above all.
//!
//! Randomness comes from the OS CSPRNG via [`rand::rngs::OsRng`], and
//! character selection uses rejection sampling (`gen_range`) rather than
//! `% len`, which would quietly bias the result toward the first few
//! characters of an alphabet whose length doesn't divide 256.

use crate::error::{PassError, Result};
use rand::seq::SliceRandom;
use rand::Rng;
use zeroize::Zeroizing;

const LOWERCASE: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?";
/// Characters excluded from the sets above because they're the ones people
/// misread when copying a password off a screen: `l`/`I`/`1`, `O`/`0`.
const AMBIGUOUS: &str = "lI1O0";

/// What kind of password to produce.
#[derive(Debug, Clone)]
pub struct GeneratorOptions {
    /// Number of characters (or, for a passphrase, of words).
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    /// Include the visually ambiguous characters excluded by default.
    pub allow_ambiguous: bool,
    /// Generate a word-based passphrase instead of a character password.
    pub passphrase: bool,
    /// Separator between passphrase words.
    pub separator: String,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            allow_ambiguous: false,
            passphrase: false,
            separator: "-".to_string(),
        }
    }
}

impl GeneratorOptions {
    /// A passphrase of `words` words — the shape to use for a master
    /// password, which has to be typed from memory.
    pub fn passphrase(words: usize) -> Self {
        Self {
            length: words,
            passphrase: true,
            ..Default::default()
        }
    }
}

/// Generate a password according to `options`.
///
/// Returned in a `Zeroizing<String>` so a caller that drops it without
/// storing it doesn't leave it behind in the heap.
pub fn generate_password(options: &GeneratorOptions) -> Result<Zeroizing<String>> {
    if options.passphrase {
        return generate_passphrase(options);
    }

    if options.length == 0 {
        return Err(PassError::SecureMemory("password length must be at least 1".to_string()));
    }

    let pools = character_pools(options);
    if pools.is_empty() {
        return Err(PassError::SecureMemory(
            "no character sets enabled: pick at least one of lowercase/uppercase/digits/symbols".to_string(),
        ));
    }
    if options.length < pools.len() {
        return Err(PassError::SecureMemory(format!(
            "length {} is too short to include all {} selected character sets",
            options.length,
            pools.len()
        )));
    }

    let mut rng = rand::rngs::OsRng;
    let all: Vec<char> = pools.iter().flat_map(|p| p.iter().copied()).collect();

    // Take one character from each enabled set first, so "include digits"
    // actually means the result has a digit rather than merely being allowed
    // one, then fill the rest from the union.
    let mut chars: Vec<char> = pools
        .iter()
        .map(|pool| pool[rng.gen_range(0..pool.len())])
        .collect();
    while chars.len() < options.length {
        chars.push(all[rng.gen_range(0..all.len())]);
    }

    // Without this the first characters would always be one-per-set in a
    // fixed order, which is a pattern an attacker can exploit.
    chars.shuffle(&mut rng);

    Ok(Zeroizing::new(chars.into_iter().collect()))
}

fn character_pools(options: &GeneratorOptions) -> Vec<Vec<char>> {
    let mut pools = Vec::new();
    let mut add = |set: &str| {
        let chars: Vec<char> = set
            .chars()
            .filter(|c| options.allow_ambiguous || !AMBIGUOUS.contains(*c))
            .collect();
        if !chars.is_empty() {
            pools.push(chars);
        }
    };

    if options.lowercase {
        add(LOWERCASE);
    }
    if options.uppercase {
        add(UPPERCASE);
    }
    if options.digits {
        add(DIGITS);
    }
    if options.symbols {
        add(SYMBOLS);
    }
    pools
}

fn generate_passphrase(options: &GeneratorOptions) -> Result<Zeroizing<String>> {
    if options.length == 0 {
        return Err(PassError::SecureMemory("a passphrase needs at least 1 word".to_string()));
    }

    let mut rng = rand::rngs::OsRng;
    let words: Vec<&str> = (0..options.length)
        .map(|_| WORDLIST[rng.gen_range(0..WORDLIST.len())])
        .collect();

    Ok(Zeroizing::new(words.join(&options.separator)))
}

/// Bits of entropy a given set of options produces, for showing the user how
/// strong the result actually is.
pub fn entropy_bits(options: &GeneratorOptions) -> f64 {
    let alphabet = if options.passphrase {
        WORDLIST.len()
    } else {
        character_pools(options).iter().map(Vec::len).sum()
    };

    if alphabet <= 1 || options.length == 0 {
        return 0.0;
    }
    options.length as f64 * (alphabet as f64).log2()
}

/// A short, deliberately plain English wordlist for passphrases.
///
/// 256 words gives 8 bits each, so word count maps to entropy without
/// arithmetic: 6 words = 48 bits, 8 words = 64. Every word is 3-6 letters,
/// unambiguous to spell, and has no near-homophone in the list, because the
/// only reason to use a passphrase is that a human has to retype it.
const WORDLIST: [&str; 256] = [
    "able", "acid", "acre", "aged", "airy", "alarm", "album", "alien", "alley", "amber", "amend", "ample",
    "anchor", "angle", "ankle", "apple", "april", "apron", "arena", "argue", "armor", "arrow", "aside", "asset",
    "atlas", "attic", "audio", "aunt", "avoid", "awake", "award", "aware", "bacon", "badge", "bagel", "baker",
    "balmy", "banjo", "barge", "basil", "basin", "batch", "beach", "beacon", "beard", "beast", "belt", "bench",
    "berry", "bike", "birch", "bison", "blade", "blaze", "blend", "bliss", "block", "bloom", "board", "boast",
    "bolt", "bonus", "boost", "booth", "bound", "brace", "brave", "bread", "brick", "brisk", "broad", "brook",
    "brush", "buddy", "bugle", "bunch", "bunny", "cabin", "cable", "cacao", "cadet", "camel", "canal", "candy",
    "canoe", "canvas", "cargo", "carve", "cedar", "chalk", "charm", "chase", "cheek", "chess", "chief", "chime",
    "chirp", "cider", "cinema", "civic", "clamp", "clash", "clean", "cliff", "cloak", "clock", "cloud", "clove",
    "coach", "coast", "cobra", "cocoa", "comet", "coral", "couch", "cover", "coyote", "crane", "crate", "creek",
    "crisp", "crown", "crumb", "curve", "cycle", "daisy", "dance", "dawn", "debut", "decoy", "delta", "dense",
    "depot", "diary", "diner", "ditch", "dizzy", "dock", "dough", "dozen", "draft", "drama", "dress", "drift",
    "drum", "dusk", "eagle", "early", "earth", "easel", "east", "echo", "elbow", "elder", "elite", "ember",
    "empty", "envoy", "epoch", "equal", "essay", "ether", "event", "exact", "extra", "fable", "fancy", "fence",
    "fern", "ferry", "fever", "fiber", "field", "final", "flame", "flask", "fleet", "flint", "flock", "flute",
    "focus", "foggy", "forge", "forum", "fossil", "frost", "fruit", "fudge", "gadget", "galaxy", "gauge", "genre",
    "ghost", "giant", "ginger", "glade", "gleam", "globe", "glove", "grace", "grain", "grape", "grasp", "green",
    "grid", "grove", "guard", "guest", "guide", "gulf", "habit", "hedge", "hero", "hinge", "hobby", "honey",
    "horse", "hotel", "human", "humid", "ideal", "igloo", "image", "index", "inlet", "irony", "island", "ivory",
    "jacket", "jelly", "jewel", "jolly", "judge", "juice", "jumbo", "kayak", "kettle", "kite", "knack", "koala",
    "label", "lace", "lagoon", "lamp", "lance", "large", "laser", "latch", "layer", "leaf", "ledge", "lemon",
    "level", "lever", "light", "lilac",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn default_password_has_requested_length_and_every_set() {
        let options = GeneratorOptions::default();
        let password = generate_password(&options).unwrap();

        assert_eq!(password.chars().count(), 20);
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| SYMBOLS.contains(c)));
    }

    #[test]
    fn ambiguous_characters_are_excluded_by_default() {
        for _ in 0..50 {
            let password = generate_password(&GeneratorOptions::default()).unwrap();
            assert!(
                !password.chars().any(|c| AMBIGUOUS.contains(c)),
                "generated an ambiguous character: {}",
                password.as_str()
            );
        }
    }

    #[test]
    fn disabled_sets_are_really_absent() {
        let options = GeneratorOptions {
            length: 32,
            symbols: false,
            digits: false,
            uppercase: false,
            ..Default::default()
        };
        let password = generate_password(&options).unwrap();
        assert!(password.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn passwords_are_not_repeated() {
        let options = GeneratorOptions::default();
        let generated: HashSet<String> = (0..100)
            .map(|_| generate_password(&options).unwrap().to_string())
            .collect();
        assert_eq!(generated.len(), 100, "generator produced a duplicate");
    }

    #[test]
    fn rejects_impossible_requests() {
        let no_sets = GeneratorOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(generate_password(&no_sets).is_err());

        let too_short = GeneratorOptions {
            length: 2,
            ..Default::default()
        };
        assert!(generate_password(&too_short).is_err(), "4 sets cannot fit in 2 characters");

        let zero = GeneratorOptions {
            length: 0,
            ..Default::default()
        };
        assert!(generate_password(&zero).is_err());
    }

    #[test]
    fn passphrase_has_the_requested_word_count() {
        let options = GeneratorOptions::passphrase(6);
        let phrase = generate_password(&options).unwrap();

        assert_eq!(phrase.split('-').count(), 6);
        assert!(phrase.chars().all(|c| c.is_ascii_lowercase() || c == '-'));
    }

    #[test]
    fn wordlist_is_exactly_256_distinct_words() {
        // The "one word = 8 bits" claim in `entropy_bits` depends on both.
        let unique: HashSet<&str> = WORDLIST.iter().copied().collect();
        assert_eq!(unique.len(), 256, "wordlist has duplicates");
    }

    #[test]
    fn entropy_matches_the_documented_figures() {
        // 256-word list, 8 bits per word.
        assert_eq!(entropy_bits(&GeneratorOptions::passphrase(6)), 48.0);

        // Character password over the full default alphabet.
        let bits = entropy_bits(&GeneratorOptions::default());
        assert!(bits > 100.0, "20 characters should clear 100 bits, got {bits}");
    }
}
