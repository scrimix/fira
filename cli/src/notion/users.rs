//! Matching Fira users to Notion users: by email, then by exact name.

use std::collections::HashMap;

use serde_json::Value;
use uuid::Uuid;

use crate::fira::User;

#[derive(Debug, Clone)]
pub struct Person {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
}

impl Person {
    pub fn from_json(v: &Value) -> Option<Person> {
        if v["type"] != "person" {
            return None;
        }
        Some(Person {
            id: v["id"].as_str()?.to_string(),
            name: v["name"].as_str().unwrap_or_default().to_string(),
            email: v["person"]["email"].as_str().map(str::to_string),
        })
    }
}

#[derive(Default)]
pub struct Matching {
    pub to_notion: HashMap<Uuid, String>,
    pub to_fira: HashMap<String, Uuid>,
    /// Why a Fira user has no Notion match.
    pub why: HashMap<Uuid, String>,
}

fn norm(name: &str) -> String {
    name.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

pub fn matching(fira: &[User], notion: &[Person]) -> Matching {
    let mut m = Matching::default();
    for u in fira {
        let by_email: Vec<&Person> = notion
            .iter()
            .filter(|p| p.email.as_deref().is_some_and(|e| e.eq_ignore_ascii_case(&u.email)))
            .collect();
        let found = match by_email.as_slice() {
            [p] => Ok(*p),
            _ => {
                let by_name: Vec<&Person> = notion.iter().filter(|p| !u.name.trim().is_empty() && norm(&p.name) == norm(&u.name)).collect();
                match by_name.as_slice() {
                    [p] => Ok(*p),
                    [] => Err("no Notion user with this email or name".to_string()),
                    many => Err(format!("ambiguous: {} Notion users named \"{}\"", many.len(), u.name)),
                }
            }
        };
        match found {
            Ok(p) => {
                m.to_notion.insert(u.id, p.id.clone());
                m.to_fira.insert(p.id.clone(), u.id);
            }
            Err(why) => {
                m.why.insert(u.id, why);
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fira(id: u128, name: &str, email: &str) -> User {
        User { id: Uuid::from_u128(id), email: email.into(), name: name.into(), active: true, member: true }
    }

    fn person(id: &str, name: &str, email: Option<&str>) -> Person {
        Person { id: id.into(), name: name.into(), email: email.map(str::to_string) }
    }

    #[test]
    fn email_then_name() {
        let f = [fira(1, "Maya Chen", "maya@x.io"), fira(2, "Ann Lee", "ann@x.io"), fira(3, "Bo Wu", "bo@x.io"), fira(4, "Cy D", "cy@x.io")];
        let n = [
            person("a", "M. Chen", Some("MAYA@x.io")),
            person("b", "ann  lee", None),
            person("c", "Bo Wu", None),
            person("d", "Bo Wu", None),
        ];
        let m = matching(&f, &n);
        assert_eq!(m.to_notion[&Uuid::from_u128(1)], "a");
        assert_eq!(m.to_notion[&Uuid::from_u128(2)], "b");
        assert!(m.why[&Uuid::from_u128(3)].starts_with("ambiguous: 2"));
        assert!(m.why[&Uuid::from_u128(4)].starts_with("no Notion user"));
        assert_eq!(m.to_fira["a"], Uuid::from_u128(1));
    }
}
