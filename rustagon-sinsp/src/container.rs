use std::fmt::Debug;
use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerMetadata {
    pub name: String,
    pub image: String,
}

pub trait ContainerLookup: Debug + Send + Sync {
    fn lookup(&self, container_id: &str) -> io::Result<Option<ContainerMetadata>>;
}

#[derive(Debug, Clone)]
pub struct FixtureContainerLookup {
    root: PathBuf,
}

impl FixtureContainerLookup {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl ContainerLookup for FixtureContainerLookup {
    fn lookup(&self, container_id: &str) -> io::Result<Option<ContainerMetadata>> {
        if !is_container_id(container_id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "container id must be 12-64 hexadecimal characters",
            ));
        }

        let path = self.root.join(format!("{container_id}.metadata"));
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        parse_metadata(&contents).map(Some)
    }
}

pub fn container_id_from_cgroup(cgroup_path: &str) -> Option<String> {
    cgroup_path
        .split(['/', '-', ':', '.'])
        .rev()
        .find(|component| is_container_id(component))
        .map(str::to_owned)
}

fn is_container_id(value: &str) -> bool {
    (12..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_metadata(contents: &str) -> io::Result<ContainerMetadata> {
    let mut name = None;
    let mut image = None;

    for line in contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let Some((key, value)) = line.split_once('=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "container metadata lines must use key=value",
            ));
        };
        match key.trim() {
            "name" => name = Some(value.trim().to_owned()),
            "image" => image = Some(value.trim().to_owned()),
            _ => {}
        }
    }

    match (name, image) {
        (Some(name), Some(image)) => Ok(ContainerMetadata { name, image }),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "container metadata requires name and image",
        )),
    }
}
