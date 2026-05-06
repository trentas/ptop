# Contributing to ptop

Thanks for taking the time to contribute. This guide covers the basics —
the design rationale lives in [`CLAUDE.md`](CLAUDE.md).

## Development setup

ptop is Linux-only at runtime (eBPF). Tests and `go vet` work on any host
thanks to build tags, but anything that exercises the eBPF lane needs Linux.

```bash
git clone https://github.com/trentas/ptop.git
cd ptop
make           # default: gen + vet + test (both lanes) + build-ebpf
```

ptop targets Linux exclusively. If your dev host isn't Linux, run a VM
(any flavor — the project has no preference) with kernel 5.8+, `clang`,
`libbpf-dev`, `bpftool`, and Go 1.22+ installed.

## Running

```bash
# full mode (eBPF, needs root)
sudo ./bin/ptop --pid <PID>

# /proc-only mode (no root)
./bin/ptop --pid <PID> --no-ebpf
```

## Tests

```bash
make test         # default lane
make test-all     # default + -tags=ebpf (requires `make gen` to have run)
make vet          # go vet ./... in both lanes
```

Always run `make` before submitting a PR. CI runs both lanes on
`ubuntu-latest`; failures block the merge.

## Commit style

- Prefix the subject with the area: `tui:`, `collector:`, `ebpf:`,
  `infra:`, `docs:`, `make:`, `ci:`. The goreleaser changelog buckets
  releases by these prefixes.
- Imperative mood: "add X", "fix Y" — not "added", "fixes".
- Keep subjects under ~70 characters. Use the body for context.
- One focused change per PR. Refactors and feature work don't share commits.
- Reference the issue you're closing in the body (`closes #NN`) when
  applicable.

## Pull requests

- Fork → branch → PR against `main`.
- The PR template asks for a summary and a test plan — fill it in.
- Don't bypass hooks (`--no-verify`) or signing. If a hook fails, fix the
  underlying issue.
- Keep diffs minimal. New abstractions need a real second caller; three
  similar lines beat a premature helper.

## Style

- No CGO beyond what cilium/ebpf already pulls in.
- No CLI framework — `flag` is the entrypoint contract.
- No logging library — `fmt.Fprintln(os.Stderr, ...)` is enough.
- Default to writing **no comments**. Only document the *why* when it would
  surprise a future reader.
- Build tags for OS/eBPF gating: `//go:build linux && ebpf` for real code,
  `//go:build !linux || !ebpf` for stubs that fail `Start` cleanly.

## Reporting issues

- **Bugs**: include kernel version (`uname -r`), distro, the exact command
  you ran, and the stderr output. The bug template covers this.
- **Security**: see [`SECURITY.md`](SECURITY.md) — don't open public issues.
- **Feature requests**: explain the use case before the proposed solution.

## License

By contributing, you agree your changes are released under the
[MIT License](LICENSE).
