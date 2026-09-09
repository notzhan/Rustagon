use serde::Deserialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginVersion {
    pub name: String,
    pub version: String,
}

impl PluginVersion {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct PluginRequirement {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub alternatives: Vec<PluginRequirement>,
}

pub(crate) fn requirements_satisfied(
    groups: &[Vec<PluginRequirement>],
    plugins: &[PluginVersion],
) -> Result<(), String> {
    for group in groups {
        for requirement in group {
            if requirement
                .alternatives
                .iter()
                .any(|alternative| alternative.name == requirement.name)
            {
                return Err(format!(
                    "plugin requirement '{}' repeats its name in alternatives",
                    requirement.name
                ));
            }
            let candidates = std::iter::once(requirement).chain(requirement.alternatives.iter());
            if !candidates.into_iter().any(|candidate| {
                plugins.iter().any(|plugin| {
                    plugin.name == candidate.name
                        && version_at_least(&plugin.version, &candidate.version)
                })
            }) {
                return Err(format!(
                    "plugin '{}' version {} is required; plugin loading is not implemented",
                    requirement.name, requirement.version
                ));
            }
        }
    }
    Ok(())
}

fn version_at_least(actual: &str, required: &str) -> bool {
    parse_version(actual)
        .zip(parse_version(required))
        .is_some_and(|(actual, required)| actual >= required)
}

fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.');
    let version = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(version)
}
