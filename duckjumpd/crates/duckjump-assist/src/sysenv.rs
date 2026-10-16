//! Running the system's tools (gst-launch-1.0, screenshot commands) from
//! inside an AppImage. Its AppRun points LD_LIBRARY_PATH, GST_PLUGIN_*,
//! GIO_*… at the libraries bundled in $APPDIR; a system binary started with
//! that environment loads them instead of its own and dies (seen as
//! "failed to fill whole buffer" when gst-launch exits at once).

use std::ffi::{OsStr, OsString};
use std::process::Command;

/// What to change in the environment for a child: variables to drop and
/// the PATH to set, given the current variables and $APPDIR.
fn host_env(vars: impl Iterator<Item = (OsString, OsString)>, appdir: &OsStr) -> (Vec<OsString>, Option<OsString>) {
    let appdir = appdir.to_string_lossy().trim_end_matches('/').to_string();
    let mut remove = Vec::new();
    let mut path = None;
    if appdir.is_empty() {
        return (remove, path);
    }
    for (k, v) in vars {
        let v = v.to_string_lossy().to_string();
        if !v.contains(&appdir) {
            continue;
        }
        if k == "PATH" {
            let kept: Vec<&str> = v.split(':').filter(|p| !p.starts_with(&appdir)).collect();
            path = Some(OsString::from(kept.join(":")));
        } else {
            remove.push(k);
        }
    }
    (remove, path)
}

/// `Command::new(program)` with the host's environment, not the AppImage's.
pub fn command(program: impl AsRef<OsStr>) -> Command {
    let mut cmd = Command::new(program);
    if let Some(appdir) = std::env::var_os("APPDIR") {
        let (remove, path) = host_env(std::env::vars_os(), &appdir);
        for k in remove {
            cmd.env_remove(k);
        }
        if let Some(p) = path {
            cmd.env("PATH", p);
        }
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_appimage_environment() {
        let vars = [
            ("PATH", "/tmp/.mount_x/usr/bin:/usr/local/bin:/usr/bin"),
            ("LD_LIBRARY_PATH", "/tmp/.mount_x/usr/lib"),
            ("GST_PLUGIN_SYSTEM_PATH_1_0", "/tmp/.mount_x/usr/lib/gstreamer-1.0"),
            ("APPDIR", "/tmp/.mount_x"),
            ("WAYLAND_DISPLAY", "wayland-0"),
            ("HOME", "/home/u"),
        ]
        .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let (mut remove, path) = host_env(vars.into_iter(), OsStr::new("/tmp/.mount_x/"));
        remove.sort();
        assert_eq!(remove, ["APPDIR", "GST_PLUGIN_SYSTEM_PATH_1_0", "LD_LIBRARY_PATH"].map(OsString::from));
        assert_eq!(path, Some(OsString::from("/usr/local/bin:/usr/bin")));
    }

    #[test]
    fn outside_an_appimage_nothing_changes() {
        let (remove, path) = host_env([(OsString::from("PATH"), OsString::from("/usr/bin"))].into_iter(), OsStr::new(""));
        assert!(remove.is_empty() && path.is_none());
    }
}
