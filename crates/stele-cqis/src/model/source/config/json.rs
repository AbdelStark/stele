//! RFC-0025 source architecture §2: strict bounded JSON tree, including annotations.
use super::super::json::Json;
use super::{number::Number, Budget, Error, LIMIT};
use alloc::{string::String, vec::Vec};

pub(super) enum Value {
    Null,
    Boolean(bool),
    String(String),
    Number(Number),
    Array(Vec<Value>),
    Object(Object),
}
pub(super) struct Object(Vec<(String, Value)>);
impl Object {
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.0
            .binary_search_by(|(key, _)| key.as_str().cmp(name))
            .ok()
            .map(|i| &self.0[i].1)
    }
    pub fn required(&self, name: &str) -> Result<&Value, Error> {
        self.get(name).ok_or(Error::SourceFields)
    }
    pub fn fields(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v))
    }
}
impl Value {
    pub fn null(&self) -> bool {
        matches!(self, Self::Null)
    }
    pub fn string(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn unsigned(&self) -> Option<u64> {
        if let Self::Number(n) = self {
            n.unsigned()
        } else {
            None
        }
    }
    pub fn ratio(&self, maximum: u64) -> Result<(u64, u64), Error> {
        if let Self::Number(n) = self {
            n.ratio(maximum)
        } else {
            Err(Error::SourceRational)
        }
    }
}
pub(super) fn parse(raw: &[u8], budget: &mut Budget) -> Result<Object, Error> {
    if raw.len() > LIMIT {
        return Err(Error::Capacity);
    }
    let mut json = Json::new(raw)?;
    let value = parse_value(&mut json, budget, &mut 0, 1)?;
    json.end()?;
    if let Value::Object(object) = value {
        Ok(object)
    } else {
        Err(Error::SourceJson)
    }
}
fn node(count: &mut usize, depth: u8) -> Result<(), Error> {
    if depth > 32 {
        return Err(Error::SourceDepth);
    }
    *count += 1;
    if *count > 65536 {
        return Err(Error::Capacity);
    }
    Ok(())
}
fn string(json: &mut Json<'_>, budget: &mut Budget) -> Result<String, Error> {
    let s = json.string(budget)?;
    if s.len() > 65535 {
        return Err(Error::SourceString);
    }
    Ok(s)
}
fn parse_value(
    json: &mut Json<'_>,
    budget: &mut Budget,
    count: &mut usize,
    depth: u8,
) -> Result<Value, Error> {
    node(count, depth)?;
    Ok(match json.peek() {
        Some(b'{') => {
            json.byte(b'{')?;
            let mut fields: Vec<(String, Value)> = Vec::new();
            let mut first = true;
            while json.next(&mut first, b'}')? {
                node(count, depth + 1)?;
                let key = string(json, budget)?;
                json.byte(b':')?;
                let value = parse_value(json, budget, count, depth + 1)?;
                budget.push(&mut fields, (key, value))?;
            }
            fields.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            if fields.windows(2).any(|p| p[0].0 == p[1].0) {
                return Err(Error::SourceDuplicate);
            }
            Value::Object(Object(fields))
        }
        Some(b'[') => {
            json.byte(b'[')?;
            let mut values = Vec::new();
            let mut first = true;
            while json.next(&mut first, b']')? {
                let value = parse_value(json, budget, count, depth + 1)?;
                budget.push(&mut values, value)?;
            }
            Value::Array(values)
        }
        Some(b'"') => Value::String(string(json, budget)?),
        _ => match json.atom() {
            b"null" => Value::Null,
            b"true" => Value::Boolean(true),
            b"false" => Value::Boolean(false),
            raw => Value::Number(Number::parse(raw, budget)?),
        },
    })
}
