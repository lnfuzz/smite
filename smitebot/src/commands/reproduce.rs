//! Crash reproduction: replay a single input against the campaign's target in
//! local Docker.
//!
//! Runs the campaign's Docker image once with `SMITE_INPUT` pointed at the given
//! input (the same `LocalRunner` path `scripts/coverage-report.sh` uses), streams
//! the target's output to the terminal, and interprets nothing — the logs are the
//! deliverable. `--attach` allocates an interactive TTY so the run can be watched
//! live. Nyx-mode reproduction is a later phase.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Args;

use crate::config::Target;
use crate::state::CampaignState;

/// Command handler for `smitebot reproduce`.
pub struct ReproduceCommand;

/// CLI arguments for `smitebot reproduce`.
#[derive(Debug, Args)]
pub struct ReproduceArgs {
    /// Campaign ID whose Docker image and target to reproduce against.
    campaign_id: String,
    /// Input file (e.g. a crash from a runner's `crashes/`) to replay.
    #[arg(short = 'i', long)]
    input: PathBuf,
    /// Allocate an interactive TTY so the run can be watched live.
    #[arg(long)]
    attach: bool,
}

impl ReproduceCommand {
    /// Replays `input` against the campaign's Docker target.
    ///
    /// Returns `true` once the container has run to completion regardless of its
    /// exit status (the target's output, not the exit code, is the result), and
    /// `false` only on an operational failure: unknown campaign, missing input,
    /// missing image, or a Docker spawn error.
    pub fn execute(args: &ReproduceArgs) -> bool {
        let Some(runs_dir) = CampaignState::runs_dir() else {
            log::error!("unable to determine home directory");
            return false;
        };

        let state_path = runs_dir.join(&args.campaign_id).join("state.json");
        let state = match CampaignState::load(&state_path) {
            Ok(s) => s,
            Err(e) => {
                log::error!("{e}");
                log::error!(
                    "campaign '{}' not found; list campaigns with: ls {}",
                    args.campaign_id,
                    runs_dir.display()
                );
                return false;
            }
        };

        // Resolve to an absolute path: Docker `-v` requires one, and this also
        // rejects a missing input up front. Mount the parent directory and pass
        // the file's basename via SMITE_INPUT so colons in AFL crash names (e.g.
        // `id:000000,sig:06,...`) never appear in the bind-mount spec.
        let input = match fs::canonicalize(&args.input) {
            Ok(p) => p,
            Err(e) => {
                log::error!("input file not found: {} ({e})", args.input.display());
                return false;
            }
        };
        if !input.is_file() {
            log::error!("input is not a regular file: {}", input.display());
            return false;
        }
        // canonicalize yields an absolute path ending in the file's name.
        let parent = input.parent().expect("canonical input path has a parent");
        let basename = input
            .file_name()
            .expect("canonical input path has a file name")
            .to_string_lossy();

        if !docker_image_exists(&state.image) {
            log::error!(
                "Docker image '{}' not found; build it with: smitebot build --target {} --scenario {}",
                state.image,
                state.target,
                state.scenario
            );
            return false;
        }

        let run_args = docker_run_args(&state.image, state.target, parent, &basename, args.attach);
        log::info!(
            "reproducing {} against {} (image {})",
            input.display(),
            state.target,
            state.image
        );
        match Command::new("docker").args(&run_args).status() {
            Ok(_) => true,
            Err(e) => {
                log::error!("failed to run docker: {e}");
                false
            }
        }
    }
}

/// Reports whether a Docker image is present locally.
///
/// Uses `docker image inspect`, whose stdout (the image JSON) is discarded — only
/// the exit status matters.
fn docker_image_exists(image: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", image])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// Builds the `docker run` argument list for a single reproduction.
///
/// Mirrors `scripts/coverage-report.sh`: mount the input's parent directory
/// read-only at `/corpus` and point `SMITE_INPUT` at `/corpus/<basename>`; the
/// per-target entrypoint is `/<target>-scenario`. `--attach` adds `-it`.
fn docker_run_args(
    image: &str,
    target: Target,
    parent: &Path,
    basename: &str,
    attach: bool,
) -> Vec<String> {
    let mut args = vec!["run".to_string(), "--rm".to_string()];
    if attach {
        args.push("-it".to_string());
    }
    // ponytail: paths under ~/.smitebot are UTF-8 in practice; `display()`
    // lossiness would only bite a non-UTF-8 corpus path, a non-goal for v1.
    args.push("-v".to_string());
    args.push(format!("{}:/corpus:ro", parent.display()));
    args.push("-e".to_string());
    args.push(format!("SMITE_INPUT=/corpus/{basename}"));
    args.push(image.to_string());
    args.push(format!("/{target}-scenario"));
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_run_args_mounts_parent_and_passes_basename() {
        // A colon-laden AFL crash name must stay inside SMITE_INPUT, never in the
        // bind-mount spec (which is delimited by colons).
        let parent = PathBuf::from("/home/u/.smitebot/runs/c/crashes");
        let args = docker_run_args(
            "smite-lnd-encrypted_bytes",
            Target::Lnd,
            &parent,
            "id:000000,sig:06,src:000000",
            false,
        );
        assert!(args.contains(&"/home/u/.smitebot/runs/c/crashes:/corpus:ro".to_string()));
        assert!(args.contains(&"SMITE_INPUT=/corpus/id:000000,sig:06,src:000000".to_string()));
    }

    #[test]
    fn docker_run_args_adds_it_only_with_attach() {
        let parent = PathBuf::from("/tmp");
        let attached = docker_run_args("img", Target::Cln, &parent, "in", true);
        let detached = docker_run_args("img", Target::Cln, &parent, "in", false);
        assert!(attached.contains(&"-it".to_string()));
        assert!(!detached.contains(&"-it".to_string()));
    }

    #[test]
    fn docker_run_args_entrypoint_is_per_target() {
        let parent = PathBuf::from("/tmp");
        let args = docker_run_args("img", Target::Eclair, &parent, "in", false);
        assert_eq!(args.last().unwrap(), "/eclair-scenario");
    }

    #[test]
    fn docker_run_args_ordering_image_before_entrypoint_flags_before_image() {
        // docker run [flags] <image> <cmd> — image must come after all flags.
        let parent = PathBuf::from("/tmp");
        let args = docker_run_args("myimage", Target::Ldk, &parent, "in", false);
        let image_pos = args.iter().position(|a| a == "myimage").unwrap();
        let v_pos = args.iter().position(|a| a == "-v").unwrap();
        let e_pos = args.iter().position(|a| a == "-e").unwrap();
        assert!(v_pos < image_pos, "-v must appear before image");
        assert!(e_pos < image_pos, "-e must appear before image");
        assert_eq!(args.last().unwrap(), "/ldk-scenario");
        assert!(args.contains(&"--rm".to_string()));
    }

    #[test]
    fn docker_run_args_handles_spaces_in_parent_path() {
        // Spaces in the corpus path must survive intact in the bind-mount spec;
        // args go direct to Command (not a shell), so no quoting is needed.
        let parent = PathBuf::from("/home/u/my campaigns/crashes");
        let args = docker_run_args("img", Target::Lnd, &parent, "crash", false);
        assert!(args.contains(&"/home/u/my campaigns/crashes:/corpus:ro".to_string()));
    }
}
