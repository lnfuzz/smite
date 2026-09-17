//! Crash reproduction: replay a single input against the campaign's target in
//! local Docker.
//!
//! Runs the campaign's Docker image once with `SMITE_INPUT` pointed at the given
//! input (the same `LocalRunner` path `scripts/coverage-report.sh` uses), streaming
//! the target's output to the terminal.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Args;

use crate::config::Target;
use crate::state::CampaignState;
use crate::utils::docker_image_id;

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
}

impl ReproduceCommand {
    /// Replays `input` against the campaign's target in Docker.
    ///
    /// Returns `true` once the container has run to completion regardless of its
    /// exit status (the target's output, not the exit code, is the result), and
    /// `false` only on an operational failure: unknown campaign, missing input,
    /// missing image, or a Docker spawn error.
    pub fn execute(args: &ReproduceArgs) -> bool {
        let (state, _) = match CampaignState::load_campaign(&args.campaign_id) {
            Ok(x) => x,
            Err(e) => {
                log::error!("{e}");
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
        // docker run takes string arguments, so reject a non-UTF-8 path rather than
        // silently mangling the mount spec. canonicalize guarantees a parent and a
        // file name, so `None` here means the path is not valid UTF-8.
        let (Some(parent), Some(basename)) = (
            input.parent().and_then(Path::to_str),
            input.file_name().and_then(|name| name.to_str()),
        ) else {
            log::error!("input path is not valid UTF-8: {}", input.display());
            return false;
        };

        let Some(image_id) = docker_image_id(&state.image) else {
            log::error!(
                "Docker image '{}' not found; build it with: smitebot build --target {} --scenario {}",
                state.image,
                state.target,
                state.scenario
            );
            return false;
        };
        // A campaign's image can be rebuilt under the same tag during development,
        // so a matching name is not a matching image. Warn on a digest mismatch and
        // point at the campaign's smite commit for an exact rebuild.
        if image_id != state.image_digest {
            log::warn!(
                "Docker image '{}' digest {} does not match the campaign's {}; results may differ.",
                state.image,
                image_id,
                state.image_digest,
            );
        }

        log::info!(
            "reproducing {} against {} (image {})",
            input.display(),
            state.target,
            state.image
        );
        let run_args = docker_run_args(&state.image, state.target, parent, basename);
        match Command::new("docker").args(&run_args).status() {
            Ok(_) => true,
            Err(e) => {
                log::error!("failed to run docker: {e}");
                false
            }
        }
    }
}

/// Builds the `docker run` argument list for a single reproduction.
///
/// Mirrors `scripts/coverage-report.sh`: mount the input's parent directory
/// read-only at `/corpus` and point `SMITE_INPUT` at `/corpus/<basename>`; the
/// per-target entrypoint is `/<target>-scenario`.
fn docker_run_args(image: &str, target: Target, parent: &str, basename: &str) -> Vec<String> {
    vec![
        "run".to_string(),
        "--rm".to_string(),
        "-v".to_string(),
        format!("{parent}:/corpus:ro"),
        "-e".to_string(),
        format!("SMITE_INPUT=/corpus/{basename}"),
        image.to_string(),
        format!("/{target}-scenario"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_run_args_mounts_parent_and_passes_basename() {
        // A colon-laden AFL crash name must stay inside SMITE_INPUT, never in the
        // bind-mount spec (which is delimited by colons).
        let args = docker_run_args(
            "smite-lnd-encrypted_bytes",
            Target::Lnd,
            "/home/u/.smitebot/runs/c/crashes",
            "id:000000,sig:06,src:000000",
        );
        assert!(args.contains(&"/home/u/.smitebot/runs/c/crashes:/corpus:ro".to_string()));
        assert!(args.contains(&"SMITE_INPUT=/corpus/id:000000,sig:06,src:000000".to_string()));
    }

    #[test]
    fn docker_run_args_entrypoint_is_per_target() {
        let args = docker_run_args("img", Target::Eclair, "/tmp", "in");
        assert_eq!(args.last().unwrap(), "/eclair-scenario");
    }

    #[test]
    fn docker_run_args_places_every_flag_before_the_image() {
        // docker run [flags] <image> <cmd> — every flag must precede the image,
        // and the per-target entrypoint is the final argument.
        let args = docker_run_args("myimage", Target::Ldk, "/tmp", "in");
        let image_pos = args.iter().position(|a| a == "myimage").unwrap();
        for flag in ["--rm", "-v", "-e"] {
            let pos = args
                .iter()
                .position(|a| a == flag)
                .unwrap_or_else(|| panic!("{flag} missing from args"));
            assert!(pos < image_pos, "{flag} must appear before the image");
        }
        assert_eq!(args.last().unwrap(), "/ldk-scenario");
    }

    #[test]
    fn docker_run_args_handles_spaces_in_parent_path() {
        // Spaces in the corpus path must survive intact in the bind-mount spec;
        // args go direct to Command (not a shell), so no quoting is needed.
        let args = docker_run_args("img", Target::Lnd, "/home/u/my campaigns/crashes", "crash");
        assert!(args.contains(&"/home/u/my campaigns/crashes:/corpus:ro".to_string()));
    }
}
