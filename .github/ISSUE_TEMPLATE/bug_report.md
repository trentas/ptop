---
name: Bug report
about: Something is broken or behaves unexpectedly
title: 'bug: '
labels: bug
---

## What happened

<!-- A clear, concrete description. Include the exact command you ran. -->

## What you expected

<!-- What should have happened instead. -->

## Reproduction

```bash
# the exact command
sudo ./bin/ptop --pid <PID>
```

## Environment

- ptop version: <!-- output of `ptop --version` -->
- Kernel: <!-- output of `uname -r` -->
- Distro: <!-- e.g. Ubuntu 24.04, Debian 12, Fedora 40 -->
- Architecture: <!-- amd64 / arm64 -->
- Build mode: <!-- eBPF / --no-ebpf -->
- Privileges: <!-- root / setcap / unprivileged -->
- Capabilities: <!-- output of `ptop --caps` — it names which collectors your
     privileges will actually run, which is usually the answer for "an axis is
     all zeros" -->

## Output

<!-- stderr output, especially any messages before the TUI starts. -->

```
<paste here>
```

## Additional context

<!-- Anything else: kernel sysctls (`unprivileged_bpf_disabled`), AppArmor /
SELinux state, container runtime, etc. -->
