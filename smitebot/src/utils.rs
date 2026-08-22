//! Small helpers shared across smitebot commands.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::CampaignConfig;

/// Returns the current Unix timestamp in seconds.
pub fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before Unix epoch")
        .as_secs()
}

/// Returns true if `path` exists and has at least one executable bit set.
pub fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path).is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

/// Wraps a string in single quotes for safe interpolation into a shell command.
///
/// Embedded single quotes are escaped with the standard `'\''` idiom. Used for
/// every value that enters a tmux shell command string.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Finds an executable named `tool` on the process `PATH`.
pub fn find_in_path(tool: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    find_in_path_with_path(tool, &path_var)
}

/// Finds an executable tool using an explicit PATH value, mainly for tests.
fn find_in_path_with_path(tool: &str, path_var: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path_var)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file() && is_executable(candidate))
}

/// Runs `scripts/setup-nyx.sh` to prepare the Nyx sharedir.
pub fn setup_nyx(config: &CampaignConfig, image: &str) -> bool {
    let script = config.smite_dir.join("scripts").join("setup-nyx.sh");
    if !script.exists() {
        log::error!("setup-nyx.sh not found: {}", script.display());
        return false;
    }

    let status = match Command::new(&script)
        .arg(&config.sharedir)
        .arg(image)
        .arg(&config.aflpp_path)
        .status()
    {
        Ok(status) => status,
        Err(e) => {
            log::error!("failed to run setup-nyx.sh: {e}");
            return false;
        }
    };

    if !status.success() {
        log::error!("setup-nyx.sh failed with {status}");
        return false;
    }

    log::info!("Nyx sharedir ready at {}", config.sharedir.display());
    true
}

/// Pins the calling thread, and every process it later spawns, to `cpu`.
///
/// # Errors
/// Returns an error if `cpu` is out of range or is not an online CPU this
/// process is allowed to run on.
pub fn pin_to_cpu(cpu: usize) -> Result<(), String> {
    // `CPU_SET` writes a bit at `cpu` in a fixed-size mask, so an index past the
    // mask has to be rejected before the call rather than after.
    let max = libc::CPU_SETSIZE as usize;
    if cpu >= max {
        return Err(format!("CPU {cpu} is out of range (0..{max})"));
    }

    // SAFETY: `set` is zero-initialized before use, `CPU_SET` writes within it
    // given the bound check above, and `sched_setaffinity` reads exactly
    // `size_of::<cpu_set_t>()` bytes from the pointer. A pid of 0 means the
    // calling thread.
    let failed = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, size_of::<libc::cpu_set_t>(), &raw const set) != 0
    };
    if failed {
        return Err(format!(
            "failed to pin to CPU {cpu}: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Runs `cmd` and returns its trimmed stdout, or `None` if it fails to spawn or
/// exits unsuccessfully.
pub fn command_stdout(cmd: &mut Command) -> Option<String> {
    let output = cmd.output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Returns a local Docker image's ID (content digest), or `None` if the image is
/// not present. The value matches the `image_digest` recorded in `state.json`.
pub fn docker_image_id(image: &str) -> Option<String> {
    command_stdout(
        Command::new("docker")
            .args(["inspect", "--format={{.Id}}"])
            .arg(image),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn pin_to_cpu_rejects_an_out_of_range_cpu() {
        // Past the mask `CPU_SET` can address; must be caught before the call,
        // since setting a bit out of bounds would be undefined behavior.
        assert!(pin_to_cpu(libc::CPU_SETSIZE as usize).is_err());
        assert!(pin_to_cpu(usize::MAX).is_err());
    }

    #[test]
    fn pin_to_cpu_binds_the_calling_thread() {
        // Affinity is per-thread, and this runs on the test's own thread, so
        // pinning here leaves the rest of the suite alone. Pin to a CPU the
        // process is already allowed on so a restricted cpuset does not fail it.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_ZERO(&mut set) };

        let size = size_of::<libc::cpu_set_t>();
        assert_eq!(
            unsafe { libc::sched_getaffinity(0, size, &raw mut set) },
            0,
            "sched_getaffinity failed"
        );

        let allowed = (0..libc::CPU_SETSIZE as usize)
            .find(|&cpu| unsafe { libc::CPU_ISSET(cpu, &set) })
            .expect("process is allowed on at least one CPU");

        pin_to_cpu(allowed).unwrap();

        let mut pinned: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        unsafe { libc::CPU_ZERO(&mut pinned) };

        assert_eq!(
            unsafe { libc::sched_getaffinity(0, size, &raw mut pinned) },
            0
        );
        assert!(unsafe { libc::CPU_ISSET(allowed, &pinned) });
        assert_eq!(unsafe { libc::CPU_COUNT(&pinned) }, 1);
    }

    #[test]
    fn find_in_path_with_path_finds_existing_executable() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().unwrap();
        let binary_path = tempdir.path().join("afl-fuzz");
        fs::write(&binary_path, "#!/bin/sh\n").unwrap();
        // Ensure the test binary is executable regardless of umask defaults.
        let mut perms = fs::metadata(&binary_path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&binary_path, perms).unwrap();

        let path_value = OsString::from(tempdir.path());
        let found = find_in_path_with_path("afl-fuzz", &path_value).unwrap();
        assert_eq!(found, binary_path);
    }

    #[test]
    fn find_in_path_with_path_ignores_non_executable_file() {
        let tempdir = tempfile::tempdir().unwrap();
        let binary_path = tempdir.path().join("afl-fuzz");
        fs::write(&binary_path, "#!/bin/sh\n").unwrap();

        let path_value = OsString::from(tempdir.path());
        let found = find_in_path_with_path("afl-fuzz", &path_value);
        assert!(found.is_none());
    }

    #[test]
    fn shell_quote_wraps_in_single_quotes() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn shell_quote_escapes_embedded_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn is_executable_detects_permission_bits() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("tool");
        fs::write(&path, "#!/bin/sh\n").unwrap();

        assert!(!is_executable(&path));

        // Flip the executable bit explicitly to validate the permission check.
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).unwrap();

        assert!(is_executable(&path));
    }
}
