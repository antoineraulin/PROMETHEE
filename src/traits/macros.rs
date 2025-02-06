// factory_macro.rs
#[macro_export]

macro_rules! method_fromraw_map {
    (
        $( $str:literal => $type:path ),+ $(,)?
    ) => {
        // Expand into a phf::Map<&'static str, fn(&RawMethod) -> Box<dyn RuleTrait>>
        phf::phf_map! {
            $(
                $str => |raw: &crate::methods::RawMethod| {
                    Box::new(<$type as crate::RuleTrait>::from_raw(raw.clone()).unwrap())
                        as Box<dyn crate::RuleTrait>
                },
            )+
        }
    };
}
