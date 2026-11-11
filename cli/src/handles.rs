//! Short assignee handles: `maya.c` for "Maya Chen".
//!
//! Emails stay out of the documents. A handle is the first name, a dot,
//! and as many leading letters of the last name as it takes to be unique
//! among the project's *members*. Members only, so that a former member
//! who is merely referenced by an old task can't change anyone's handle
//! from one run to the next.
//!
//! Reading is exact: a written handle must equal some member's current
//! handle. Nothing is matched by prefix, so when a handle stops fitting
//! (a rename, or a second "Maya C…" joins and both become `maya.ch` /
//! `maya.co`) the old handle matches nobody and the CLI asks, rather than
//! silently landing on someone else.

use std::collections::HashMap;

use uuid::Uuid;

pub struct Person<'a> {
    pub id: Uuid,
    pub name: &'a str,
    pub member: bool,
}

/// Lowercased words of a display name, punctuation dropped
/// ("Mary-Jane O'Brien" → ["maryjane", "obrien"]).
fn words(name: &str) -> Vec<String> {
    name.split_whitespace()
        .map(|w| w.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect::<String>())
        .filter(|w| !w.is_empty())
        .collect()
}

fn first_last(name: &str) -> (String, Option<String>) {
    let w = words(name);
    match w.len() {
        0 => ("user".into(), None),
        1 => (w[0].clone(), None),
        n => (w[0].clone(), Some(w[n - 1].clone())),
    }
}

fn prefix(s: &str, k: usize) -> String {
    s.chars().take(k).collect()
}

pub fn compute(people: &[Person]) -> HashMap<Uuid, String> {
    let mut out: HashMap<Uuid, String> = HashMap::new();
    let parsed: Vec<(Uuid, String, Option<String>, bool)> = people
        .iter()
        .map(|p| {
            let (f, l) = first_last(p.name);
            (p.id, f, l, p.member)
        })
        .collect();

    // Members: shortest unique surname prefix within the same first name.
    let mut members: Vec<&(Uuid, String, Option<String>, bool)> = parsed.iter().filter(|p| p.3).collect();
    members.sort_by_key(|p| p.0);
    for (id, first, last, _) in &members {
        let handle = match last {
            None => first.clone(),
            Some(last) => {
                let others: Vec<&String> = members
                    .iter()
                    .filter(|o| o.0 != *id && o.1 == *first)
                    .filter_map(|o| o.2.as_ref())
                    .collect();
                let len = last.chars().count();
                let k = (1..=len).find(|&k| {
                    let p = prefix(last, k);
                    !others.iter().any(|o| o.starts_with(&p))
                });
                format!("{first}.{}", prefix(last, k.unwrap_or(len)))
            }
        };
        out.insert(*id, handle);
    }
    dedupe(&mut out, members.iter().map(|m| m.0).collect());

    // Former members and other referenced people: full surname, and never
    // a handle a member has.
    let mut rest: Vec<&(Uuid, String, Option<String>, bool)> = parsed.iter().filter(|p| !p.3).collect();
    rest.sort_by_key(|p| p.0);
    for (id, first, last, _) in rest {
        let mut h = match last {
            Some(l) => format!("{first}.{l}"),
            None => first.clone(),
        };
        let base = h.clone();
        let mut n = 2;
        while out.values().any(|v| *v == h) {
            h = format!("{base}-{n}");
            n += 1;
        }
        out.insert(*id, h);
    }
    out
}

/// Identical names get `-2`, `-3`, … in id order.
fn dedupe(out: &mut HashMap<Uuid, String>, order: Vec<Uuid>) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for id in order {
        let h = out[&id].clone();
        let n = seen.entry(h.clone()).or_insert(0);
        *n += 1;
        if *n > 1 {
            out.insert(id, format!("{h}-{n}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handles(people: &[(u128, &str, bool)]) -> Vec<String> {
        let ps: Vec<Person> = people.iter().map(|(id, name, member)| Person { id: Uuid::from_u128(*id), name, member: *member }).collect();
        let h = compute(&ps);
        people.iter().map(|(id, _, _)| h[&Uuid::from_u128(*id)].clone()).collect()
    }

    #[test]
    fn first_name_and_surname_initial() {
        assert_eq!(handles(&[(1, "Maya Chen", true), (2, "Bob Reyes", true)]), ["maya.c", "bob.r"]);
    }

    #[test]
    fn surname_grows_until_unique() {
        assert_eq!(handles(&[(1, "Maya Chen", true), (2, "Maya Cole", true), (3, "Maya Diaz", true)]), ["maya.ch", "maya.co", "maya.d"]);
        // One surname is a prefix of the other.
        assert_eq!(handles(&[(1, "Ann Chen", true), (2, "Ann Cheng", true)]), ["ann.chen", "ann.cheng"]);
    }

    #[test]
    fn identical_and_single_names() {
        assert_eq!(handles(&[(1, "Maya Chen", true), (2, "Maya Chen", true)]), ["maya.chen", "maya.chen-2"]);
        assert_eq!(handles(&[(1, "Cher", true), (2, "Cher Bono", true)]), ["cher", "cher.b"]);
        assert_eq!(handles(&[(1, "Mary-Jane O'Brien", true)]), ["maryjane.o"]);
    }

    #[test]
    fn non_members_never_shift_member_handles() {
        // A former "Maya Cole" referenced by an old task: Maya Chen stays maya.c.
        assert_eq!(handles(&[(1, "Maya Chen", true), (2, "Maya Cole", false)]), ["maya.c", "maya.cole"]);
        assert_eq!(handles(&[(1, "Maya C", true), (2, "Maya C", false)]), ["maya.c", "maya.c-2"]);
    }
}
