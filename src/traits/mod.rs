pub mod cli;
pub mod macros;
pub mod rule;

pub use rule::Rule;
pub use rule::RuleTrait;
pub use rule::R;

pub use log::{debug, error, info, trace, warn};
