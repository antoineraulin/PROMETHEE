use serde::ser::{Serialize, SerializeSeq, Serializer};

use super::data_structures::*;

impl Serialize for LocalGroupPolicyObject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // We'll implement serialization by telling the serializer we're a tuple of four strings
        let mut seq = serializer.serialize_seq(Some(4))?;
        seq.serialize_element(&self.configuration)?;
        seq.serialize_element(&self.registry_key)?;
        seq.serialize_element(&self.value_name)?;
        seq.serialize_element(&self.action)?;
        seq.end()
    }
}

pub fn serialize_entries<W: std::io::Write>(
    w: &mut W,
    entries: &[LocalGroupPolicyObject],
) -> std::io::Result<()> {
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            writeln!(w)?; // blank line between entries
        }
        writeln!(
            w,
            "{}",
            serde_plain::to_string(&entry.configuration)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        )?;
        writeln!(w, "{}", entry.registry_key)?;
        writeln!(w, "{}", entry.value_name)?;
        writeln!(
            w,
            "{}",
            serde_plain::to_string(&entry.action)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        )?;
    }
    Ok(())
}
