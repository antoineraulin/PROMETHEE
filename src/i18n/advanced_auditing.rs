use phf::phf_map;

const AUDIT_CSV_HEADER_FR_FR: phf::Map<&str, &str> = phf_map! {
    "computer_name" => "Nom d’ordinateur",
    "target" => "Cible de stratégie",
    "sub_category" => "Sous-catégorie",
    "guid" => "GUID de sous-catégorie",
    "inclusion_parameter" => "Paramètre d’inclusion",
    "exclusion_parameter" => "Paramètre d’exclusion",
    "parameter_value" => "Valeur de paramètre",
};

const AUDIT_CSV_PARAMETERS_FR_FR : phf::Map<&str, &str> = phf_map! {
    "disabled" => "Désactivé",
    "no_auditing" => "Pas d’audit",
    "success" => "Réussite",
    "failure" => "Échec",
    "success_and_failure" => "Succès et échec",
};

const AUDITPOL_COMMON_FR_FR : phf::Map<&str, &str> = phf_map! {
    "error_indicator" => "L'erreur 0x"
};

pub const AUDIT_CSV_HEADER_I18N: phf::Map<&str, &phf::Map<&str, &str>> = phf_map! {
    "fr-FR" => &AUDIT_CSV_HEADER_FR_FR,
};

pub const AUDIT_CSV_PARAMETERS_I18N: phf::Map<&str, &phf::Map<&str, &str>> = phf_map! {
    "fr-FR" => &AUDIT_CSV_PARAMETERS_FR_FR,
};

pub const AUDITPOL_COMMON_I18N: phf::Map<&str, &phf::Map<&str, &str>> = phf_map! {
    "fr-FR" => &AUDITPOL_COMMON_FR_FR,
};