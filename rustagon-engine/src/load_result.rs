#[derive(Debug, Default, Clone)]
pub struct LoadResult {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub schema_validation: String,
}

impl LoadResult {
    pub fn success() -> Self {
        Self {
            ok: true,
            schema_validation: "ok".into(),
            ..Default::default()
        }
    }
}
