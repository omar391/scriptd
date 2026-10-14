# mcpu

mcpu monitors high-CPU background CLI tools and helpers. It can prompt you to
enroll a verified executable even when its current ownership or process-group
state means it cannot yet be cleaned up.

Each one-minute sample retains a CPU baseline. The first sample warms the
sampler; gaps, sleep, restarts, missing observations, identity changes, policy
changes, low CPU, or loss of eligibility reset timing. CPU must remain strictly
above 50% for two observed minutes before an eligible command is enrolled.
Minute samples establish observed continuity; short CPU dips between samples
cannot be ruled out.

The native macOS enrollment window shows the tool name, canonical executable
path, observed CPU and memory, and the verified ownership state, including
when a process was reparented to launchd after its owner exited. It offers only
**Add** and **Exclude**. Add has a per-tool timer in minutes, initially 30. The
window has no close button or Escape dismissal and remains open until Add or
Exclude is durably saved. A missing UI heartbeat is reported but never closes
the prompt or starts a response deadline. Unanswered requests are stored before
presentation and remain pending if the UI process or desktop session stops;
they are presented again when the UI is available.

Enrollment verifies the process generation, executable, user, registered
service state, and its live ownership chain. System processes, other users, app
bundles, registered services and their descendants, shared runtimes, and
terminal/editor-owned work remain protected. Verified background helpers may
still reach the prompt when they have children, are session leaders, or were
reparented to launchd; the prompt reports that ownership state. A mismatched
original-parent unique ID distinguishes an orphan from a process started
directly by launchd.

On macOS, the build packages the AppKit helper with `/usr/bin/swiftc`. At first
presentation, scriptd installs that helper as a private app bundle in its
Application Support state directory and launches it as a separate process.

An Add decision is stored privately in
~/Library/Application Support/scriptd/mcpu/policy.json and binds the canonical
path, file fingerprint, and code-signing identity. It starts a fresh monitoring
period. Cleanup is limited to a verified orphaned leaf with no controlling
terminal, alone in its process group, with no surviving group leader and no
registered service. MCPU rechecks the process generation, executable, owner,
group membership, service state, exclusion, and approval immediately before
each signal. After at least 60 seconds, it repeats those checks before SIGKILL.
Each signal targets one PID and is bound to macOS's process-generation
`pidversion`, so a reused PID cannot receive the signal. This uses a private
libproc interface; if that interface is unavailable or rejects the process
generation, scriptd sends no signal and has no PID-only fallback. RAM is
informational.

System processes, other users, app bundles and helpers, launchd services and
their descendants, terminal/editor-owned work, shared interpreters/runtimes,
and uncertain or unsigned executable identities are protected from enrollment.
Active owners, child workloads, session leaders, shared process groups, and any
unresolved service or identity state withhold cleanup. A path exclusion always
overrides an approval. If policy storage, the native UI, launchd service
inspection, process-group inspection, or executable verification fails,
cleanup authorization is withheld.

## Configuration

- cpu_threshold — minimum threshold, in percentage points; values below 50 are
  rejected. The default is 50.
- exclude_apps — additional process names to protect.

The module is invoked by the global trigger engine. Its production trigger is
configured in service.yaml and mcpu remains disabled there until the reviewed
generation is activated.

## Files

- module.rs — scan orchestration, timing, and guarded signals.
- module/process.rs — retained CPU sampling, process identity, and protections.
- module/policy.rs — private atomic approvals, exclusions, and pending requests.
- module/enrollment_ui.swift — persistent native Add/Exclude window.
