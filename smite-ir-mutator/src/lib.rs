//! AFL++ custom mutator C ABI shim.
//!
//! This crate exports the `afl_custom_*` symbols that AFL++ looks up via
//! `dlsym` when a shared library is supplied through
//! `AFL_CUSTOM_MUTATOR_LIBRARY`. The resulting `.so` (built via
//! `crate-type = ["cdylib"]`) is the *only* way AFL++ produces inputs for the
//! IR fuzzer.
//!
//! # AFL++ environment contract
//!
//! Set the following when launching `afl-fuzz`:
//! - `AFL_CUSTOM_MUTATOR_LIBRARY=/path/to/libsmite_ir_mutator.so`
//! - `AFL_CUSTOM_MUTATOR_ONLY=1` -- disable AFL++'s byte mutators. This also
//!   disables the havoc stage entirely, so we deliberately do not implement
//!   `afl_custom_havoc_mutation`.
//! - `AFL_FRAMESHIFT_DISABLE=1` -- disable AFL++'s `FrameShift` analysis that
//!   bypasses our custom mutators. This was an AFL++ bug fixed upstream in
//!   commit eddb2701b022351fb34b696ccf923bb856e9d953.
//!
//! # Logging
//!
//! Logging is opt-in: [`afl_custom_init`] installs a logger only when
//! `RUST_LOG` is set. With `RUST_LOG` unset, every `log::*!` callsite is a
//! no-op and AFL's stderr stays clean. Useful filters:
//! - `RUST_LOG=smite_ir_mutator::trim=debug` -- show the simplification
//!   candidate and the result of each truncation attempt.
//! - `RUST_LOG=debug` -- everything this crate emits.
//!
//! # Buffer ownership
//!
//! `MutatorState` owns a `Vec<u8>` (`out_buf`) that holds the serialized
//! mutated program. When AFL++ requests a new input from us, we hand it a
//! pointer to that `Vec<u8>` along with its length. AFL++ never saves the
//! pointer across calls, so we're safe to reuse the buffer for the next input.

use std::os::raw::{c_char, c_uint, c_void};
use std::slice;

use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use smite_ir::generators::AnyGenerator;
use smite_ir::minimizers::{
    CommonSubexpressionEliminator, DeadCodeEliminator, MinimizeSession, Minimizer, Truncator,
};
use smite_ir::mutators::{
    GeneratorInsertionMutator, InputSwapMutator, InstructionDeleteMutator,
    InstructionReorderMutator, OperationParamMutator,
};
use smite_ir::{Generator, Mutator, Program, ProgramBuilder};

/// Mutator state owned by AFL++ across calls. Allocated by [`afl_custom_init`],
/// destroyed by [`afl_custom_deinit`].
struct MutatorState {
    rng: SmallRng,
    /// Reusable buffer for serialized mutated programs. The pointer to its
    /// contents is what we hand back to AFL++ when it requests an input.
    out_buf: Vec<u8>,
    /// Active truncation session and the final cleanup candidate awaiting AFL++ feedback.
    trim: Option<TrimSession>,
    /// Reusable null-terminated description string returned by
    /// [`afl_custom_describe`].
    description: Vec<u8>,
    /// Sequence of actions taken in the last [`afl_custom_fuzz`] call, used by
    /// [`afl_custom_describe`] to name queue entries.
    last_sequence: Vec<&'static str>,
}

impl MutatorState {
    fn new(seed: u32) -> Self {
        Self {
            rng: SmallRng::seed_from_u64(u64::from(seed)),
            out_buf: Vec::new(),
            trim: None,
            description: Vec::new(),
            last_sequence: vec!["init"],
        }
    }

    /// Generates a fresh program from scratch by delegating to one of the
    /// registered generators, picked by weight.
    fn generate_fresh(&mut self) -> Program {
        let mut builder = ProgramBuilder::new();
        AnyGenerator::choose(&mut self.rng).generate(&mut builder, &mut self.rng);
        self.last_sequence.clear();
        self.last_sequence.push("fresh");
        builder.build()
    }

    /// Applies a random number of stacked mutations to `program`. The stack
    /// count is a power of two in `[1, 16]` to give a mix of small tweaks and
    /// larger leaps per execution, similar in spirit to AFL++'s havoc stage.
    /// Records the ordered list of mutator names in `last_sequence`.
    fn mutate_stacked(&mut self, program: &mut Program) {
        self.last_sequence.clear();
        // Power-of-two stack count: 1, 2, 4, 8, or 16 mutations.
        let stack = 1u32 << self.rng.random_range(0..=4);
        for _ in 0..stack {
            // Uniform pick between the available mutators.
            let name = match self.rng.random_range(0..5) {
                0 => {
                    OperationParamMutator.mutate(program, &mut self.rng);
                    "op-param"
                }
                1 => {
                    InputSwapMutator.mutate(program, &mut self.rng);
                    "input-swap"
                }
                2 => {
                    InstructionDeleteMutator.mutate(program, &mut self.rng);
                    "instr-delete"
                }
                3 => {
                    InstructionReorderMutator.mutate(program, &mut self.rng);
                    "instr-reorder"
                }
                4 => {
                    let mutator =
                        GeneratorInsertionMutator::new(AnyGenerator::choose(&mut self.rng));
                    mutator.mutate(program, &mut self.rng);
                    "gen-insert"
                }
                _ => unreachable!("random_range() bound out of sync with match arms"),
            };
            self.last_sequence.push(name);
        }
    }

    /// Postcard-encodes `program` into `self.out_buf`, reusing the existing
    /// allocation. Returns `true` if the encoded length fits within `max_size`.
    fn serialize(&mut self, program: &Program, max_size: usize) -> bool {
        let mut buf = std::mem::take(&mut self.out_buf);
        buf.clear();
        match postcard::to_extend(program, buf) {
            Ok(buf) => {
                self.out_buf = buf;
                self.out_buf.len() <= max_size
            }
            Err(_) => false,
        }
    }
}

/// Tracks the truncation phase followed by one DCE/CSE cleanup attempt.
struct TrimSession {
    /// Engine-independent prefix search, driven by AFL++ coverage feedback.
    truncator: Truncator,
    /// Final cleanup candidate, populated only after truncation finishes.
    cleanup: Option<Program>,
}

// -- AFL++ custom mutator ABI -------------------------------------------------

/// Warns about any missing AFL++ environment variables required by this
/// mutator.
#[cfg(not(test))]
fn warn_on_unset_afl_env() {
    let unset: Vec<&str> = ["AFL_CUSTOM_MUTATOR_ONLY", "AFL_FRAMESHIFT_DISABLE"]
        .into_iter()
        .filter(|name| std::env::var(name).unwrap_or_default() != "1")
        .collect();

    if unset.is_empty() {
        return;
    }

    let bar = "=".repeat(72);
    eprintln!("\n{bar}");
    eprintln!("[smite-ir-mutator] WARNING: required AFL++ env vars are not set to 1:");
    for name in &unset {
        eprintln!("  - {name}");
    }
    eprintln!("Fuzzing will be inefficient and may produce false-positive crashes.");
    eprintln!("{bar}\n");

    std::thread::sleep(std::time::Duration::from_secs(10));
}

/// Allocates a new [`MutatorState`] and returns an opaque pointer to it. AFL++
/// passes this pointer back on every function call as the `data` argument.
///
/// Also installs `simple_logger` if `RUST_LOG` is set, so `log::*!` callsites
/// in this crate become live. Without `RUST_LOG` no logger is installed and
/// every callsite is a no-op. Set
/// `RUST_LOG=smite_ir_mutator::trim=debug` to see trim decisions.
///
/// # Safety
///
/// The returned pointer is heap-allocated via `Box::into_raw` and must be freed
/// by a matching call to [`afl_custom_deinit`].
///
/// # Panics
///
/// Panics if `RUST_LOG` is set and `simple_logger` fails to initialize.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_init(_afl: *const c_void, seed: c_uint) -> *mut c_void {
    #[cfg(not(test))]
    warn_on_unset_afl_env();
    if std::env::var_os("RUST_LOG").is_some() {
        simple_logger::init_with_env().expect("logger initializes");
    }
    Box::into_raw(Box::new(MutatorState::new(seed))).cast::<c_void>()
}

/// Frees the [`MutatorState`] previously returned by [`afl_custom_init`].
///
/// # Safety
///
/// `data` must be a pointer previously returned by [`afl_custom_init`] and
/// not yet freed. After this call, `data` must not be used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_deinit(data: *mut c_void) {
    drop(unsafe { Box::from_raw(data.cast::<MutatorState>()) });
}

/// Generates one mutated input from the seed at `buf`.
///
/// If `buf_size == 0` or postcard decoding fails, falls back to generating a
/// fresh program. Otherwise applies a stack of mutations (see
/// [`MutatorState::mutate_stacked`]) to the decoded program; with 5%
/// probability of regenerating from scratch anyway to avoid getting stuck on a
/// single seed.
///
/// `*out_buf` is always set to a valid, non-null pointer before returning (even
/// on failure, where we return 0 and point at our empty buffer). The buffer at
/// `*out_buf` remains valid until the next call to `afl_custom_fuzz`.
///
/// # Safety
///
/// - `data` must be a pointer returned by [`afl_custom_init`].
/// - `buf` must point to `buf_size` readable bytes.
/// - `out_buf` must be a valid, writable pointer to a `*const u8` slot.
/// - `_add_buf` is unused; we export `afl_custom_splice_optout` so AFL++ never
///   populates it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_fuzz(
    data: *mut c_void,
    buf: *mut u8,
    buf_size: usize,
    out_buf: *mut *const u8,
    _add_buf: *mut u8,
    _add_buf_size: usize,
    max_size: usize,
) -> usize {
    let state = unsafe { &mut *data.cast::<MutatorState>() };

    let generate_fresh = buf_size == 0 || state.rng.random_range(0..20) == 0;
    let program = if generate_fresh {
        state.generate_fresh()
    } else {
        let input = unsafe { slice::from_raw_parts(buf, buf_size) };
        match postcard::from_bytes::<Program>(input) {
            Ok(mut p) => {
                state.mutate_stacked(&mut p);
                p
            }
            Err(_) => state.generate_fresh(),
        }
    };

    let len = if state.serialize(&program, max_size) {
        state.out_buf.len()
    } else {
        0
    };
    unsafe { *out_buf = state.out_buf.as_ptr() };
    len
}

/// Starts a trim session for a corpus entry. Truncation runs first, then
/// the dead-code and common-subexpression passes get one cleanup attempt.
///
/// AFL drives the trim loop with `while (stage_cur < stage_max)`, where
/// `stage_max` is this function's return value and `stage_cur` is updated
/// from [`afl_custom_post_trim`]'s return.
///
/// # Returns
///
/// - `1` to start the adaptive search. [`afl_custom_post_trim`] returns `0`
///   while candidates remain, then `1` to terminate the loop.
/// - `0` to skip trimming if decoding fails or the program is empty.
///
/// # Safety
///
/// - `data` must be a pointer returned by [`afl_custom_init`].
/// - If `buf_size` is nonzero, `buf` must point to `buf_size` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_init_trim(
    data: *mut c_void,
    buf: *mut u8,
    buf_size: usize,
) -> i32 {
    let state = unsafe { &mut *data.cast::<MutatorState>() };
    state.trim = None;

    if buf_size == 0 {
        return 0;
    }

    let input = unsafe { slice::from_raw_parts(buf, buf_size) };
    let Ok(program) = postcard::from_bytes::<Program>(input) else {
        return 0;
    };
    if program.instructions.is_empty() {
        return 0;
    }

    state.trim = Some(TrimSession {
        truncator: Truncator::new(program),
        cleanup: None,
    });
    state.out_buf.resize(buf_size - 1, 0);
    1
}

/// Encodes the current candidate and hands it back to AFL++.
///
/// The pointer written into `*out_buf` borrows from `MutatorState::out_buf`
/// and remains valid until the next call into this library. It is always
/// non-null, including when the returned length is zero.
///
/// Returns 0 if there is no candidate or encoding failed. AFL++ treats a
/// zero-length result as a rejected attempt and advances through
/// [`afl_custom_post_trim`], which controls termination.
///
/// # Safety
///
/// - `data` must be a pointer returned by [`afl_custom_init`].
/// - `out_buf` must be a valid, writable pointer to a `*const u8` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_trim(data: *mut c_void, out_buf: *mut *const u8) -> usize {
    let state = unsafe { &mut *data.cast::<MutatorState>() };
    let candidate = state
        .trim
        .as_ref()
        .and_then(|trim| trim.truncator.candidate().or(trim.cleanup.as_ref()));
    let len = candidate.map_or(0, |program| {
        postcard::to_slice(program, &mut state.out_buf).map_or(0, |bytes| bytes.len())
    });
    unsafe { *out_buf = state.out_buf.as_ptr() };
    len
}

/// Passes AFL++'s coverage result to the minimization session. Rejected
/// prefixes leave the last accepted program intact.
///
/// When truncation finishes, stages one DCE/CSE candidate from the last
/// accepted prefix. AFL++ also checks that candidate before retaining it.
///
/// AFL assigns this return value to `stage_cur` and continues while
/// `stage_cur < stage_max`. Returns `0` for another attempt, or `1` to end
/// the session. AFL++ retains the last buffer whose coverage matched.
///
/// # Safety
///
/// - `data` must be a pointer returned by [`afl_custom_init`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_post_trim(data: *mut c_void, success: u8) -> i32 {
    let state = unsafe { &mut *data.cast::<MutatorState>() };
    let Some(mut trim) = state.trim.take() else {
        return 1;
    };
    let Some(candidate) = trim.truncator.candidate() else {
        // The cleanup attempt has finished. AFL++ owns the accepted output.
        return 1;
    };

    log::debug!(
        target: "smite_ir_mutator::trim",
        "prefix_len={} accepted={}",
        candidate.instructions.len(),
        success != 0,
    );
    trim.truncator.feedback(success != 0);
    if trim.truncator.candidate().is_some() {
        state.trim = Some(trim);
        return 0;
    }

    let mut cleanup = trim.truncator.program().clone();
    let dce_changed = DeadCodeEliminator.minimize(&mut cleanup);
    let cse_changed = CommonSubexpressionEliminator.minimize(&mut cleanup);
    if !dce_changed && !cse_changed {
        return 1;
    }

    log::debug!(
        target: "smite_ir_mutator::trim",
        "dce={dce_changed} cse={cse_changed}\n--- before ---\n{}--- after ---\n{cleanup}---",
        trim.truncator.program(),
    );
    trim.cleanup = Some(cleanup);
    state.trim = Some(trim);
    0
}

/// Marker symbol that tells AFL++ not to populate `add_buf` for
/// [`afl_custom_fuzz`]. AFL++ never actually calls this function -- it only
/// checks for the symbol's presence via `dlsym` and, if found, skips picking a
/// splice input before each fuzz call.
///
/// # Safety
///
/// Never invoked; the signature exists only so the symbol has the correct
/// linkage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_splice_optout(_data: *mut c_void) {}

/// Returns a null-terminated description of the most recently applied mutation.
/// AFL++ uses this when naming queue entries.
///
/// The description is trimmed to fit within `max_description_len` bytes
/// (excluding the trailing null).
///
/// # Safety
///
/// - `data` must be a pointer returned by [`afl_custom_init`].
/// - The returned pointer is owned by the [`MutatorState`] and remains valid
///   only until the next call into this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn afl_custom_describe(
    data: *mut c_void,
    max_description_len: usize,
) -> *const c_char {
    let state = unsafe { &mut *data.cast::<MutatorState>() };
    state.description.clear();
    state.description.extend_from_slice(b"smite-ir:");
    for (i, name) in state.last_sequence.iter().enumerate() {
        if i > 0 {
            state.description.push(b',');
        }
        state.description.extend_from_slice(name.as_bytes());
    }
    // Leave room for the trailing null terminator.
    if state.description.len() > max_description_len {
        state.description.truncate(max_description_len);
    }
    state.description.push(0);
    state.description.as_ptr().cast::<c_char>()
}

#[cfg(test)]
mod tests {
    use smite_ir::Operation;
    use smite_ir::generators::OpenChannelGenerator;
    use std::ffi::CStr;
    use std::ptr;

    use super::*;

    /// RAII wrapper that calls `afl_custom_init` on construction and
    /// `afl_custom_deinit` on drop.
    struct State(*mut c_void);

    impl State {
        fn new(seed: u32) -> Self {
            Self(unsafe { afl_custom_init(ptr::null(), seed) })
        }
    }

    impl Drop for State {
        fn drop(&mut self) {
            unsafe { afl_custom_deinit(self.0) };
        }
    }

    /// Calls `afl_custom_fuzz` and returns `(out, len)`. The returned pointer
    /// is borrowed from the state's internal buffer and is only valid until the
    /// next call into the library.
    fn fuzz_via_ffi(state: &State, mut input: Vec<u8>, max_size: usize) -> (*const u8, usize) {
        let mut out: *const u8 = ptr::null();
        let len = unsafe {
            afl_custom_fuzz(
                state.0,
                input.as_mut_ptr(),
                input.len(),
                &raw mut out,
                ptr::null_mut(),
                0,
                max_size,
            )
        };
        (out, len)
    }

    fn decode(out: *const u8, len: usize) -> Program {
        let bytes = unsafe { slice::from_raw_parts(out, len) };
        postcard::from_bytes(bytes).expect("decode")
    }

    fn verify_fresh_generation(state: &State) {
        let ptr = unsafe { afl_custom_describe(state.0, 64) };
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .expect("valid utf-8");
        assert_eq!(s, "smite-ir:fresh", "fresh generation did not occur");
    }

    fn seed_program_bytes() -> Vec<u8> {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut builder = ProgramBuilder::new();
        OpenChannelGenerator.generate(&mut builder, &mut rng);
        postcard::to_allocvec(&builder.build()).expect("postcard serialization")
    }

    /// `seed_program_bytes()` plus an unreferenced `LoadAmount`, so the
    /// cleanup pass has something to remove when all prefixes are rejected.
    fn reducible_seed_bytes() -> Vec<u8> {
        let bytes = seed_program_bytes();
        let mut program: Program = postcard::from_bytes(&bytes).expect("decode");
        program.instructions.push(smite_ir::Instruction {
            operation: smite_ir::Operation::LoadAmount(0xdead_beef),
            inputs: vec![],
        });
        postcard::to_allocvec(&program).expect("encode")
    }

    #[test]
    fn init_returns_nonnull() {
        let state = State::new(0);
        assert!(!state.0.is_null());
    }

    #[test]
    fn fuzz_with_empty_input_generates_fresh() {
        let state = State::new(1);
        let (out, len) = fuzz_via_ffi(&state, Vec::new(), 1 << 16);
        assert!(len > 0);
        decode(out, len);
        verify_fresh_generation(&state);
    }

    #[test]
    fn fuzz_valid_input_produces_decodable_output() {
        let state = State::new(2);
        let mut current = seed_program_bytes();
        for _ in 0..50 {
            let (out, len) = fuzz_via_ffi(&state, current, 1 << 16);
            assert!(len > 0);
            // Copy before the next call, which will overwrite the state's
            // out_buf.
            let bytes = unsafe { slice::from_raw_parts(out, len) }.to_vec();
            decode(bytes.as_ptr(), bytes.len());
            current = bytes;
        }
    }

    #[test]
    fn fuzz_with_garbage_input_generates_fresh() {
        let state = State::new(3);
        let (out, len) = fuzz_via_ffi(&state, vec![0xFFu8; 16], 1 << 16);
        assert!(len > 0);
        decode(out, len);
        verify_fresh_generation(&state);
    }

    #[test]
    fn fuzz_returns_zero_on_oversize_with_non_null_out_buf() {
        // max_size = 4 is smaller than any encoded program; expect the fuzz
        // path to return 0 and still leave *out_buf pointing at something
        // non-null.
        let state = State::new(4);
        let (out, len) = fuzz_via_ffi(&state, Vec::new(), 4);
        assert_eq!(len, 0);
        assert!(!out.is_null());
    }

    #[test]
    fn describe_lists_stacked_mutator_sequence() {
        let state = State::new(6);
        // Loop until we hit the stacked-mutation branch (5% of calls generate
        // fresh instead).
        for _ in 0..10 {
            let _ = fuzz_via_ffi(&state, seed_program_bytes(), 1 << 16);
            let ptr = unsafe { afl_custom_describe(state.0, 256) };
            let s = unsafe { CStr::from_ptr(ptr) }
                .to_str()
                .expect("valid utf-8");
            let suffix = s
                .strip_prefix("smite-ir:")
                .expect("smite-ir: prefix on description");
            if suffix == "fresh" {
                continue;
            }
            for name in suffix.split(',') {
                assert!(
                    name == "op-param"
                        || name == "input-swap"
                        || name == "instr-delete"
                        || name == "instr-reorder"
                        || name == "gen-insert",
                    "unexpected mutator name in description: {name:?} (full: {s:?})",
                );
            }
            return;
        }
        panic!("no stacked mutations of existing input after 10 attempts");
    }

    #[test]
    fn describe_respects_max_description_len() {
        let state = State::new(7);
        let _ = fuzz_via_ffi(&state, Vec::new(), 1 << 16);
        // Cap the description at 5 bytes.
        let ptr = unsafe { afl_custom_describe(state.0, 5) };
        let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
        assert!(
            bytes.len() <= 5,
            "description must leave room for the null terminator within max_description_len",
        );
    }

    #[test]
    fn splice_optout_symbol_exists() {
        // AFL++ should never call this function, but invoking it should not
        // crash either.
        unsafe { afl_custom_splice_optout(ptr::null_mut()) };
    }

    // -- Trim tests --

    fn init_trim_via_ffi(state: &State, mut input: Vec<u8>) -> i32 {
        unsafe { afl_custom_init_trim(state.0, input.as_mut_ptr(), input.len()) }
    }

    fn trim_via_ffi(state: &State) -> (*const u8, usize) {
        let mut out: *const u8 = ptr::null();
        let len = unsafe { afl_custom_trim(state.0, &raw mut out) };
        (out, len)
    }

    fn post_trim_via_ffi(state: &State, success: bool) -> i32 {
        unsafe { afl_custom_post_trim(state.0, u8::from(success)) }
    }

    #[test]
    fn trim_init_returns_1_when_reduction_possible() {
        let state = State::new(0);
        let rv = init_trim_via_ffi(&state, reducible_seed_bytes());
        assert_eq!(rv, 1);
    }

    #[test]
    fn trim_init_returns_0_for_empty_program() {
        let state = State::new(0);
        let empty_program = ProgramBuilder::new().build();
        let bytes = postcard::to_allocvec(&empty_program).expect("encode");
        let rv = init_trim_via_ffi(&state, bytes);
        assert_eq!(rv, 0);
    }

    #[test]
    fn trim_init_clears_pending_candidate_for_garbage() {
        let state = State::new(0);
        assert_eq!(init_trim_via_ffi(&state, reducible_seed_bytes()), 1);
        assert_eq!(init_trim_via_ffi(&state, vec![0xFF; 16]), 0);
        let (out, len) = trim_via_ffi(&state);
        assert!(!out.is_null());
        assert_eq!(len, 0);
    }

    #[test]
    fn trim_yields_candidate_after_init() {
        let state = State::new(0);
        init_trim_via_ffi(&state, reducible_seed_bytes());
        let (out, len) = trim_via_ffi(&state);
        assert!(len > 0);
        decode(out, len);
    }

    #[test]
    fn trim_search_uses_acceptance_and_rejection_to_choose_the_next_prefix() {
        let mut builder = ProgramBuilder::new();
        for blocks in 1..=8 {
            builder.append(Operation::MineBlocks(blocks), &[]);
        }
        let program = builder.build();
        let input = postcard::to_allocvec(&program).expect("encode");
        let input_len = input.len();
        let state = State::new(0);
        let stop = init_trim_via_ffi(&state, input);
        assert_eq!(stop, 1);

        // Simulate coverage from only the first three instructions.
        for (prefix_len, next_index) in [(4, 0), (2, 0), (3, stop)] {
            let (out, len) = trim_via_ffi(&state);
            assert!(len > 0 && len < input_len);
            assert_eq!(
                decode(out, len).instructions,
                program.instructions[..prefix_len]
            );
            assert_eq!(post_trim_via_ffi(&state, prefix_len >= 3), next_index);
        }
        assert_eq!(trim_via_ffi(&state).1, 0);
    }

    #[test]
    fn trim_runs_cleanup_on_the_last_accepted_prefix() {
        let mut builder = ProgramBuilder::new();
        let channel_id = builder.append(Operation::LoadChannelId([0; 32]), &[]);
        let script = builder.append(Operation::LoadBytes(vec![0x51]), &[]);
        for blocks in 1..=6 {
            builder.append(Operation::MineBlocks(blocks), &[]);
        }
        builder.append(Operation::SendShutdown, &[channel_id, script]);
        let program = builder.build();
        assert!(!DeadCodeEliminator.minimize(&mut program.clone()));
        let input = postcard::to_allocvec(&program).expect("encode");

        for cleanup_accepted in [false, true] {
            let state = State::new(0);
            assert_eq!(init_trim_via_ffi(&state, input.clone()), 1);

            // First accept a four-instruction prefix, then reject shorter cuts.
            for (prefix_len, accepted) in [(4, true), (2, false), (3, false)] {
                let (out, len) = trim_via_ffi(&state);
                assert_eq!(
                    decode(out, len).instructions,
                    program.instructions[..prefix_len]
                );
                assert_eq!(post_trim_via_ffi(&state, accepted), 0);
            }

            // Removing SendShutdown makes both loads dead in the accepted prefix.
            let (out, len) = trim_via_ffi(&state);
            assert_eq!(decode(out, len).instructions, program.instructions[2..4]);
            assert_eq!(post_trim_via_ffi(&state, cleanup_accepted), 1);
            assert_eq!(trim_via_ffi(&state).1, 0);
        }
    }

    #[test]
    fn trim_runs_cleanup_even_when_every_prefix_is_rejected() {
        let mut builder = ProgramBuilder::new();
        builder.append(Operation::LoadAmount(100), &[]);
        for blocks in 1..=7 {
            builder.append(Operation::MineBlocks(blocks), &[]);
        }
        let program = builder.build();
        let input = postcard::to_allocvec(&program).expect("encode");
        let state = State::new(0);
        assert_eq!(init_trim_via_ffi(&state, input), 1);

        for prefix_len in [4, 6, 7] {
            let (out, len) = trim_via_ffi(&state);
            assert_eq!(
                decode(out, len).instructions,
                program.instructions[..prefix_len]
            );
            assert_eq!(post_trim_via_ffi(&state, false), 0);
        }

        let (out, len) = trim_via_ffi(&state);
        assert_eq!(decode(out, len).instructions, program.instructions[1..]);
        assert_eq!(post_trim_via_ffi(&state, true), 1);
    }

    #[test]
    fn trim_search_can_offer_a_serialized_empty_prefix() {
        let mut builder = ProgramBuilder::new();
        builder.append(Operation::MineBlocks(1), &[]);
        let input = postcard::to_allocvec(&builder.build()).expect("encode");

        for accepted in [false, true] {
            let state = State::new(0);
            let stop = init_trim_via_ffi(&state, input.clone());
            assert_eq!(stop, 1);
            let (out, len) = trim_via_ffi(&state);
            assert!(len > 0);
            assert_eq!(decode(out, len), ProgramBuilder::new().build());
            assert_eq!(post_trim_via_ffi(&state, accepted), stop);
        }
    }

    #[test]
    fn trim_init_does_not_overwrite_sequence() {
        // Trim is not a mutation; `last_sequence` (used by `describe` to
        // name queue entries from fuzz) must survive both the no-op and
        // successful trim paths.
        for (label, input, expected_rv) in [
            ("skipped", vec![], 0),
            ("started", reducible_seed_bytes(), 1),
        ] {
            let state = State::new(0);
            // Run a fuzz call so last_sequence has known contents.
            let _ = fuzz_via_ffi(&state, Vec::new(), 1 << 16);
            let before = unsafe { CStr::from_ptr(afl_custom_describe(state.0, 256)) }
                .to_str()
                .expect("valid utf-8")
                .to_string();
            let rv = init_trim_via_ffi(&state, input);
            assert_eq!(rv, expected_rv, "{label}");
            let after = unsafe { CStr::from_ptr(afl_custom_describe(state.0, 256)) }
                .to_str()
                .expect("valid utf-8")
                .to_string();
            assert_eq!(before, after, "{label}");
        }
    }

    #[test]
    fn trim_candidate_is_smaller_than_input() {
        let original_bytes = reducible_seed_bytes();
        let original_program: Program = postcard::from_bytes(&original_bytes).expect("decode");

        let state = State::new(0);
        init_trim_via_ffi(&state, original_bytes);

        let (out, len) = trim_via_ffi(&state);
        assert!(len > 0, "trim should yield a candidate");
        let trimmed = decode(out, len);
        assert!(
            trimmed.instructions.len() < original_program.instructions.len(),
            "trim should shrink instruction count"
        );
    }
}
