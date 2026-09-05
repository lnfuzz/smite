//! Low level FFI bindings to the Nyx agent for snapshot based fuzzing
//!
//! [Nyx](https://nyx-fuzz.com/) is a hypervisor based snapshot fuzzer that
//! runs the target inside a modified QEMU VM. After an initial setup phase
//! the VM state is snapshotted and each fuzz iteration restores the snapshot,
//! injects a new input and collects coverage. And all this without restarting the
//! target process.
//!
//! This crate compiles the C agent (`nyx-agent.c`) via `build.rs` and exposes
//! its functions to Rust. The bundled build defines `NO_PT_NYX` so the agent
//! communicates with the Nyx hypervisor through the x86 port-I/O hypercall path
//! defined in `nyx.h`.

use std::os::raw::{c_char, c_uchar};

// Exposed nyx agent functions.
//
// See docs in `smite-nyx-sys/src/nyx-agent.c`
unsafe extern "C" {
    /// Initializes the Nyx agent and returns the maximum fuzz input size
    /// (in bytes) supported by the host.
    pub fn nyx_init() -> usize;

    /// Dumps the contents of `data` to a file on the host filesystem
    /// named by the first `file_name_len` bytes of `file_name`.
    ///
    /// Useful for exporting crash logs, coverage data or other artifacts
    /// from the guest VM to the host for post-processing.
    pub fn nyx_dump_file_to_host(
        file_name: *const c_char,
        file_name_len: usize,
        data: *const c_uchar,
        len: usize,
    );

    /// Retrieves the next fuzz input from the Nyx hypervisor.
    ///
    /// On first entry this maps the payload buffer, resets coverage
    /// and takes the VM snapshot via `HYPERCALL_KAFL_USER_FAST_ACQUIRE`.
    /// Later iterations resume after that snapshot point and copy the current
    /// payload into `data`.
    ///
    /// `data` must be large enough for the full payload; the C agent does not
    /// clamp the copy to `max_size`. Pass the size returned by [`nyx_init`].
    ///
    /// Returns the actual fuzz input size.
    pub fn nyx_get_fuzz_input(data: *const c_uchar, max_size: usize) -> usize;

    /// Skips the current test case and resets the coverage bitmap and restores
    /// the VM to the snapshot state.
    /// After this call, execution resumes from the snapshot point inside
    /// [`nyx_get_fuzz_input`].
    pub fn nyx_skip();

    /// Signals the end of a test case and restores the VM to the snapshot
    /// state.
    /// After this call the execution resumes from the snapshot point inside
    /// [`nyx_get_fuzz_input`].
    pub fn nyx_release();

    /// Reports a crash to the Nyx hypervisor with the given diagnostic
    /// message.
    ///
    /// `message` must be a valid, null terminated C string. The hypervisor
    /// records this as a crash input and the message is included in the
    /// crash report.
    pub fn nyx_fail(message: *const c_char);

    /// Prints a message to the Nyx host console via `hprintf`.
    /// Messages longer than the hypervisor buffer limit are sent in chunks.
    pub fn nyx_println(message: *const c_char, size: usize);
}
