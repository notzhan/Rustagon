use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

pub fn write_pidfile(path: impl AsRef<Path>, dry_run: bool) -> io::Result<()> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() || dry_run {
        return Ok(());
    }

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    writeln!(file, "{}", std::process::id())
}
