use super::data_structures::*;
use super::errors::LgpoError;
use serde::de::value::MapDeserializer;
use serde::de::{self, IntoDeserializer, SeqAccess, Visitor};
use serde::{forward_to_deserialize_any, Deserialize};

pub struct Deserializer<I: Iterator<Item = Result<String, std::io::Error>>> {
    lines: I,
}

impl<I: Iterator<Item = Result<String, std::io::Error>>> Deserializer<I> {
    pub fn new(lines: I) -> Self {
        Deserializer { lines }
    }

    fn next_line(&mut self) -> Result<Option<String>, LgpoError> {
        match self.lines.next() {
            Some(Ok(l)) => Ok(Some(l)),
            Some(Err(e)) => Err(LgpoError::Message(e.to_string())),
            None => Ok(None),
        }
    }

    fn next_non_comment_line(&mut self) -> Result<Option<String>, LgpoError> {
        loop {
            let line = self.next_line()?;
            match line {
                Some(l) => {
                    let trimmed = l.trim();
                    if trimmed.is_empty() {
                        // blank line, skip
                        continue;
                    }
                    if trimmed.starts_with(';') {
                        // comment line, skip
                        continue;
                    }
                    return Ok(Some(l));
                }
                None => return Ok(None),
            }
        }
    }

    fn parse_entry(&mut self) -> Result<Option<LocalGroupPolicyObject>, LgpoError> {
        let config_line = match self.next_non_comment_line()? {
            Some(l) => l,
            None => return Ok(None), // no more entries
        };

        let config = serde_plain::from_str(&config_line)
            .map_err(|e| LgpoError::InvalidFormat(e.to_string()))?;

        let reg_key_line = self.next_non_comment_line()?.ok_or(LgpoError::Eof)?;
        let value_name_line = self.next_non_comment_line()?.ok_or(LgpoError::Eof)?;
        let action_line = self.next_non_comment_line()?.ok_or(LgpoError::Eof)?;

        // parse action
        let mut action = serde_plain::from_str(&action_line)
            .map_err(|e| LgpoError::InvalidFormat(e.to_string()))?;

        // Special case: For DELETEKEYS, the value_name_line contains keys to delete
        if let Action::DeleteKeys(_) = action {
            let subkeys: Vec<String> = value_name_line
                .split(';')
                .map(|s| s.trim().to_string())
                .collect();
            action = Action::DeleteKeys(subkeys);
        }

        let entry = LocalGroupPolicyObject {
            configuration: config,
            registry_key: reg_key_line,
            value_name: value_name_line,
            action,
        };

        Ok(Some(entry))
    }
}

impl<'de, I> de::Deserializer<'de> for &mut Deserializer<I>
where
    I: Iterator<Item = Result<String, std::io::Error>>,
{
    type Error = LgpoError;

    fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(de::Error::custom("deserialize_any not supported"))
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        struct Access<'a, I: Iterator<Item = Result<String, std::io::Error>>> {
            de: &'a mut Deserializer<I>,
        }

        impl<'de, 'a, I> SeqAccess<'de> for Access<'a, I>
        where
            I: Iterator<Item = Result<String, std::io::Error>>,
        {
            type Error = LgpoError;

            fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
            where
                T: de::DeserializeSeed<'de>,
            {
                match self.de.parse_entry()? {
                    Some(entry) => {
                        let val = seed.deserialize(entry.into_deserializer())?;
                        Ok(Some(val))
                    }
                    None => Ok(None),
                }
            }
        }

        visitor.visit_seq(Access { de: self })
    }

    // We implement for sequences only. The file is essentially a sequence of entries.
    forward_to_deserialize_any! {
        bool char str string bytes byte_buf map unit unit_struct newtype_struct tuple tuple_struct
        struct enum identifier ignored_any option i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64
    }
}

// Convert Entry to a serde::de::value::MapDeserializer or something similar so it can be deserialized from a custom structure.
// However, since we know we want a sequence of Entry, we can directly implement Deserialize for Entry using a custom logic.
//
// A simpler approach: manually implement Deserialize for Entry. We'll just treat Entry as something that can be "pulled" from parse_entry.
// For this to work, we can do a trick: since we know parse_entry returns Entry directly, we won't rely on a generic approach.

// Instead, we can implement IntoDeserializer for Entry to integrate with SeqAccess::next_element_seed:
impl<'de> serde::de::IntoDeserializer<'de, LgpoError> for LocalGroupPolicyObject {
    type Deserializer = MapDeserializer<'de, std::vec::IntoIter<(&'static str, String)>, LgpoError>;

    fn into_deserializer(self) -> Self::Deserializer {
        let pairs = vec![
            (
                "configuration",
                serde_plain::to_string(&self.configuration).unwrap(),
            ),
            ("registry_key", self.registry_key),
            ("value_name", self.value_name),
            ("action", serde_plain::to_string(&self.action).unwrap()),
        ];

        MapDeserializer::new(pairs.into_iter())
    }
}

impl<'de> serde::Deserialize<'de> for LocalGroupPolicyObject {
    fn deserialize<D>(deserializer: D) -> Result<LocalGroupPolicyObject, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            configuration: Configuration,
            registry_key: String,
            value_name: String,
            action: Action,
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(LocalGroupPolicyObject {
            configuration: helper.configuration,
            registry_key: helper.registry_key,
            value_name: helper.value_name,
            action: helper.action,
        })
    }
}
