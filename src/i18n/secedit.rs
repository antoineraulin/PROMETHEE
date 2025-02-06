use phf::phf_map;

static SECEDIT_COMMONS_FR_FR : phf::Map<&'static str, &'static str> = phf_map! {
    "done_100" => "Terminé : 100 pour cent",
};

pub static SECEDIT_COMMONS_I18N: phf::Map<&'static str, &'static phf::Map<&'static str, &'static str>> = phf_map! {
    "fr-FR" => &SECEDIT_COMMONS_FR_FR,
};