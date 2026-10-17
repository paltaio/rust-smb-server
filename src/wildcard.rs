//! Name matching with the wildcards of MS-FSA 2.1.4.4.
//!
//! The pattern compiles to a set of bit masks over its positions, and a
//! name is matched by walking it once while tracking every pattern position
//! reachable so far. Each name character costs a fixed number of word
//! operations per 64 pattern characters, so matching is linear in the name
//! length for patterns of filename size.

use std::collections::HashMap;

/// A compiled search pattern.
///
/// - `*` matches any sequence, `?` any single character.
/// - `<` (DOS_STAR) matches any sequence that does not contain the last `.`
///   of the name.
/// - `>` (DOS_QM) matches any single character other than `.`, and matches
///   nothing at a `.` or at the end of the name.
/// - `"` (DOS_DOT) matches a `.`, or nothing at the end of the name.
pub(crate) struct Pattern {
    /// Number of pattern characters; state `len` is the accepting state.
    len: usize,
    ignore_case: bool,
    /// Positions with an empty move to the next position: `*` and `<`.
    eps_star: Vec<u64>,
    /// Positions of `>`: an empty move before a `.` or at the end.
    eps_qm: Vec<u64>,
    /// Positions of `"`: an empty move at the end.
    eps_dot: Vec<u64>,
    /// States after a `*` that stay put while consuming any character.
    loop_star: Vec<u64>,
    /// States after a `<` that stay put while consuming any character but
    /// the last `.` of the name.
    loop_dos_star: Vec<u64>,
    /// Positions of `?`: advance on any character.
    any: Vec<u64>,
    /// Positions of `>`: advance on any character but `.`.
    not_dot: Vec<u64>,
    /// Positions of `"`: advance on `.`.
    dot: Vec<u64>,
    /// Positions of each literal character.
    literals: HashMap<char, Vec<u64>>,
}

impl Pattern {
    /// Compile `pattern`. With `ignore_case`, letters match regardless of
    /// case.
    pub(crate) fn new(pattern: &str, ignore_case: bool) -> Self {
        let chars: Vec<char> = pattern.chars().collect();
        let len = chars.len();
        let words = (len + 1).div_ceil(64);
        let zero = vec![0u64; words];
        let mut p = Self {
            len,
            ignore_case,
            eps_star: zero.clone(),
            eps_qm: zero.clone(),
            eps_dot: zero.clone(),
            loop_star: zero.clone(),
            loop_dos_star: zero.clone(),
            any: zero.clone(),
            not_dot: zero.clone(),
            dot: zero.clone(),
            literals: HashMap::new(),
        };
        for (i, &c) in chars.iter().enumerate() {
            match c {
                '*' => {
                    set(&mut p.eps_star, i);
                    set(&mut p.loop_star, i + 1);
                }
                '<' => {
                    set(&mut p.eps_star, i);
                    set(&mut p.loop_dos_star, i + 1);
                }
                '?' => set(&mut p.any, i),
                '>' => {
                    set(&mut p.eps_qm, i);
                    set(&mut p.not_dot, i);
                }
                '"' => {
                    set(&mut p.eps_dot, i);
                    set(&mut p.dot, i);
                }
                c => {
                    let key = fold(c, ignore_case);
                    set(p.literals.entry(key).or_insert_with(|| zero.clone()), i);
                }
            }
        }
        p
    }

    /// True if all of `name` matches the pattern.
    pub(crate) fn matches(&self, name: &str) -> bool {
        let name: Vec<char> = name.chars().map(|c| fold(c, self.ignore_case)).collect();
        let last_dot = name.iter().rposition(|&c| c == '.');
        let words = self.eps_star.len();
        let mut state = vec![0u64; words];
        set(&mut state, 0);
        let mut eps = vec![0u64; words];
        let mut step = vec![0u64; words];

        for (j, &c) in name.iter().enumerate() {
            self.closure(&mut state, &mut eps, c == '.', false);
            if state.iter().all(|&w| w == 0) {
                return false;
            }
            let literal = self.literals.get(&c);
            let mut carry = 0;
            for w in 0..words {
                let mut advance = self.any[w];
                if c == '.' {
                    advance |= self.dot[w];
                } else {
                    advance |= self.not_dot[w];
                }
                if let Some(mask) = literal {
                    advance |= mask[w];
                }
                let moved = state[w] & advance;
                let mut stay = state[w] & self.loop_star[w];
                if Some(j) != last_dot {
                    stay |= state[w] & self.loop_dos_star[w];
                }
                step[w] = stay | (moved << 1) | carry;
                carry = moved >> 63;
            }
            std::mem::swap(&mut state, &mut step);
        }
        self.closure(&mut state, &mut eps, false, true);
        get(&state, self.len)
    }

    /// Adds to `state` every position reachable through empty moves, before
    /// a name character that is a `.` (`at_dot`) or at the end of the name
    /// (`at_end`).
    ///
    /// Empty moves form runs of consecutive positions. Adding the reached
    /// positions to the run mask carries through each run from its lowest
    /// reached position, which marks the rest of the run in one pass.
    fn closure(&self, state: &mut [u64], eps: &mut [u64], at_dot: bool, at_end: bool) {
        for (w, e) in eps.iter_mut().enumerate() {
            *e = self.eps_star[w];
            if at_dot || at_end {
                *e |= self.eps_qm[w];
            }
            if at_end {
                *e |= self.eps_dot[w];
            }
        }
        let mut add_carry = 0u64;
        let mut shift_carry = 0u64;
        for w in 0..state.len() {
            let reached = state[w] & eps[w];
            let (sum, c1) = eps[w].overflowing_add(reached);
            let (sum, c2) = sum.overflowing_add(add_carry);
            add_carry = u64::from(c1 || c2);
            let filled = (!sum & eps[w]) | reached;
            state[w] |= (filled << 1) | shift_carry;
            shift_carry = filled >> 63;
        }
    }
}

fn set(bits: &mut [u64], i: usize) {
    bits[i / 64] |= 1 << (i % 64);
}

fn get(bits: &[u64], i: usize) -> bool {
    bits[i / 64] & (1 << (i % 64)) != 0
}

/// `c` with case folded when `ignore_case` is set: the simple uppercase
/// mapping where there is one.
fn fold(c: char, ignore_case: bool) -> char {
    if !ignore_case {
        return c;
    }
    if c.is_ascii() {
        return c.to_ascii_uppercase();
    }
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(u), None) => u,
        _ => c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pattern: &str, name: &str) -> bool {
        Pattern::new(pattern, true).matches(name)
    }

    #[test]
    fn star_and_question_mark() {
        assert!(m("*.txt", "notes.TXT"));
        assert!(!m("*.txt", "notes.txt.bak"));
        assert!(m("a?c", "abc"));
        assert!(!m("a?c", "ac"));
        assert!(m("*", ""));
        assert!(m("**a**", "xay"));
        assert!(m("a*b*c", "aXbYbZc"));
        assert!(!m("a*b*c", "aXbYbZ"));
        assert!(m("", ""));
        assert!(!m("", "a"));
    }

    #[test]
    fn dos_wildcards() {
        // DOS_STAR stops at the last dot.
        assert!(m("<.txt", "a.b.txt"));
        assert!(m("<", "abc"));
        assert!(!m("<", "a.b"));
        assert!(m("<.<", "a.b"));
        // DOS_QM matches one non-dot character, or nothing before a dot or
        // at the end.
        assert!(m(">>>", "ab"));
        assert!(m(">>.txt", "a.txt"));
        assert!(!m(">.txt", "ab.txt"));
        assert!(m(">w.txt", "ow.txt"));
        assert!(!m(">w.txt", "w.txt"));
        // DOS_DOT matches a dot, or nothing at the end.
        assert!(m("a\"", "a"));
        assert!(m("a\"", "a."));
        assert!(m("a\"b", "a.b"));
        assert!(!m("a\"b", "ab"));
        assert!(m("<\"<", "abc"));
    }

    #[test]
    fn case_rule() {
        assert!(Pattern::new("ABC*", true).matches("abcdef"));
        assert!(!Pattern::new("ABC*", false).matches("abcdef"));
        assert!(Pattern::new("\u{C9}T\u{C9}", true).matches("\u{E9}t\u{E9}"));
        assert!(!Pattern::new("\u{C9}t\u{C9}", false).matches("\u{E9}t\u{E9}"));
    }

    #[test]
    fn long_patterns_span_words() {
        let name = "x".repeat(200);
        assert!(m(&"?".repeat(200), &name));
        assert!(!m(&"?".repeat(199), &name));
        assert!(m(&format!("{}*", "?".repeat(130)), &name));
        let stars = "*".repeat(300);
        assert!(m(&format!("{stars}x{stars}"), &name));
        assert!(!m(&format!("{stars}y{stars}"), &name));
        assert!(m(&"<".repeat(64), &name));
    }

    /// The matcher against a direct backtracking implementation of the same
    /// rules, over every short pattern and name from a small alphabet.
    #[test]
    fn agrees_with_reference_on_short_inputs() {
        fn reference(p: &[char], n: &[char], j: usize, last_dot: Option<usize>) -> bool {
            let Some((&pc, rest)) = p.split_first() else {
                return j == n.len();
            };
            let here = n.get(j).copied();
            match pc {
                '*' => (j..=n.len()).any(|k| reference(rest, n, k, last_dot)),
                '<' => (j..=n.len())
                    .take_while(|&k| k == j || Some(k - 1) != last_dot)
                    .any(|k| reference(rest, n, k, last_dot)),
                '?' => here.is_some() && reference(rest, n, j + 1, last_dot),
                '>' => match here {
                    Some('.') | None => reference(rest, n, j, last_dot),
                    Some(_) => reference(rest, n, j + 1, last_dot),
                },
                '"' => match here {
                    Some('.') => reference(rest, n, j + 1, last_dot),
                    None => reference(rest, n, j, last_dot),
                    Some(_) => false,
                },
                c => here == Some(c) && reference(rest, n, j + 1, last_dot),
            }
        }

        fn all(alphabet: &[char], max_len: usize) -> Vec<String> {
            let mut out = vec![String::new()];
            let mut frontier = vec![String::new()];
            for _ in 0..max_len {
                let mut next = Vec::new();
                for s in &frontier {
                    for &c in alphabet {
                        next.push(format!("{s}{c}"));
                    }
                }
                out.extend(next.iter().cloned());
                frontier = next;
            }
            out
        }

        let patterns = all(&['a', '.', '*', '?', '<', '>', '"'], 4);
        let names = all(&['a', 'b', '.'], 4);
        for p in &patterns {
            let compiled = Pattern::new(p, false);
            let pc: Vec<char> = p.chars().collect();
            for n in &names {
                let nc: Vec<char> = n.chars().collect();
                let last_dot = nc.iter().rposition(|&c| c == '.');
                assert_eq!(
                    compiled.matches(n),
                    reference(&pc, &nc, 0, last_dot),
                    "pattern {p:?} name {n:?}"
                );
            }
        }
    }
}
