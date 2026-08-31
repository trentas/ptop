# Security policy

## Threat model

ptop runs as root (or with the capability set in [`README.md`](README.md#permissions)
— `cap_bpf`, `cap_perfmon`, `cap_sys_admin`, `cap_dac_read_search`,
`cap_sys_ptrace`) and loads eBPF programs into the kernel. Bugs in this code
path can affect the host kernel directly — we treat security reports
accordingly.

## Reporting a vulnerability

**Do not open a public issue for security reports.**

Please use GitHub's private vulnerability reporting:

1. Go to <https://github.com/trentas/ptop/security/advisories/new>
2. Provide:
   - the affected version (commit hash if from `main`)
   - kernel version (`uname -r`) and distro
   - reproduction steps and impact
   - suggested mitigation, if you have one

You should receive an acknowledgement within **5 business days**. Once a fix
is ready, we coordinate disclosure with you (typically a 30–90 day window
depending on severity).

If GitHub Security Advisories aren't an option for you, email the maintainer
listed in `go.mod` / `LICENSE`.

## Scope

In scope:
- Memory corruption, panics, or kernel issues triggered by ptop's eBPF
  programs or loader.
- Privilege escalation paths (e.g. an unprivileged process exploiting ptop
  while it's running with elevated caps).
- Snapshot/export files containing data the user didn't expect (sensitive
  paths, credentials in command lines, etc.).
- Supply chain: tampered release artifacts, compromised dependencies.

Out of scope:
- Running ptop with `--pid` against a process the operator can't legitimately
  inspect — that's an OS permission question, not a ptop bug.
- Information disclosure inherent to having `CAP_BPF` — by design, ptop
  exposes data that requires that capability.
- Denial of service via resource exhaustion when monitoring an extremely busy
  process; please open a regular issue instead.

## Hardening recommendations for operators

- Prefer a file capability over running as root — but know what you are
  granting. `CAP_SYS_ADMIN` is the gate on the uprobe PMU ptop's heap and TLS
  lanes need, and it is close to root in practice; in a container sharing the
  host pid namespace it *is* root. `cap_bpf,cap_perfmon+ep` alone is a real
  hardening choice, and it costs the `heap`, `memory` and `network` collectors
  (#117) — run `ptop --caps` to see exactly which collectors a given grant
  will run, and pick the trade knowingly rather than discovering it in the
  shape of a capture.
- Don't run ptop binaries from untrusted sources. Verify release archives
  with the published `SHA256SUMS`.
- The release binaries are built with `CGO_ENABLED=0` and no dynamic linking
  — your distro's package manager should not see ptop pulling in extra
  shared libraries.
