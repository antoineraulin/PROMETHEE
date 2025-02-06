pub mod advanced_auditing;
pub mod appx_package;
pub mod firewall;
pub mod lgpo;
pub mod local_group;
pub mod local_user;
pub mod method;
pub mod safer;
pub mod secedit;
pub mod service;
pub mod windows_capability;
pub mod windows_optional_feature;

pub use method::*;

//////////////////////////////////////////////////////
// Methods Initialization
//////////////////////////////////////////////////////

use crate::{method_fromraw_map, traits::RuleTrait};

pub static FROM_RAW_REGISTRY: phf::Map<&'static str, fn(&RawMethod) -> Box<dyn RuleTrait>> = method_fromraw_map! {
    "advanced_auditing" => advanced_auditing::AdvancedAuditing,
    "appx_package" => appx_package::AppxPackage,
    "firewall" => firewall::FirewallRule,
    "lgpo" => lgpo::LocalGroupPolicyObject,
    "local_group" => local_group::LocalGroup,
    "local_user" => local_user::LocalAccount,
    "safer" => safer::SoftwareRestrictionPolicy,
    "secedit" => secedit::SecEdit,
    "service" => service::Service,
    "windows_capability" => windows_capability::WindowsCapability,
    "windows_optional_feature" => windows_optional_feature::WindowsOptionalFeature,
};
