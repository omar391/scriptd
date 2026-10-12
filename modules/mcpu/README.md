# mcpu

mcpu monitors high-CPU processes and only manages a standalone command after
you explicitly enroll its verified executable.

Each one-minute sample retains a CPU baseline. The first sample warms the
sampler; gaps, sleep, restarts, missing observations, identity changes, policy
changes, low CPU, or loss of eligibility reset timing. CPU must remain strictly
above 50% for two observed minutes before an eligible command is enrolled.
Minute samples establish observed continuity; short CPU dips between samples
cannot be ruled out.

The native macOS enrollment window shows the tool name, canonical executable
path, observed CPU and memory, and the evidence that it is detached. It offers
only **Add** and **Exclude**. Add has a per-tool timer in minutes, initially
30. The window has no close button or Escape dismissal and remains open until
Add or Exclude is durably saved. A missing UI heartbeat is reported but never
closes the prompt or starts a response deadline. Unanswered requests are stored
before presentation and remain pending if the UI process or desktop session
stops; they are presented again when the UI is available.

Ownership is accepted only when the kernel's original-parent unique ID proves
that launchd started the process directly, and the process is an unregistered
session leader with no controlling terminal or children. The process must also
pass the executable, user, and service checks above. A current PPID of 1 alone
does not prove this: a process reparented after its owner exits retains a
different original-parent identity and remains protected. This deliberately
narrow path permits enrollment only when launchd provenance is verifiable and
no registered service owns the process.

On macOS, the build packages the AppKit helper with `/usr/bin/swiftc`. At first
presentation, scriptd installs that helper as a private app bundle in its
Application Support state directory and launches it as a separate process.

An Add decision is stored privately in
~/Library/Application Support/scriptd/mcpu/policy.json and binds the canonical
path, file fingerprint, and code-signing identity. It starts a fresh monitoring
period. Only a still-eligible process with a verified matching identity and the
complete approved high-CPU duration can receive SIGTERM. After at least 60
seconds, the process identity and protections are checked again before SIGKILL.
Each signal targets one PID and is bound to macOS's process-generation
`pidversion`, so a PID reused after revalidation cannot receive the signal. This
uses a private libproc interface; if that interface is unavailable or rejects
the process generation, scriptd sends no signal and has no PID-only fallback.
RAM is informational.

System processes, other users, app bundles and helpers, launchd services and
their descendants, terminal/editor-owned work, shared interpreters/runtimes,
commands with children, launchd-reparented workloads, and uncertain or unsigned
executable identities are protected. A path exclusion always overrides an
approval. If policy storage, the native UI, launchd service inspection, or
executable verification fails, cleanup authorization is withheld.

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
