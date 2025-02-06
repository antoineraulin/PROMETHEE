#[derive(Debug, Clone, PartialEq)]
pub struct RawMethod {
    pub method: String,
    pub target: String,
    pub option1: String,
    pub option2: String,
    pub scope: String,
    pub action: String,
}
