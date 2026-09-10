#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadInfo {
    pub tid: i64,
    pub pid: i64,
    pub ppid: i64,
    pub comm: String,
    pub exe: String,
    pub exepath: String,
    pub args: Vec<String>,
}

impl ThreadInfo {
    pub fn cmdline(&self) -> String {
        std::iter::once(self.exe.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }
}
