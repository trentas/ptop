## Summary

<!-- One paragraph: what changed and why. Lead with the user-visible effect
or the bug being fixed; "the code now does X" is implicit, "this fixes the
crash when /proc/<pid>/io is missing" is the useful framing. -->

## Test plan

<!-- How you verified the change. Be specific. -->

- [ ] `make` (default target — gen + vet + test both lanes + build-ebpf)
- [ ] Manual run: `sudo ./bin/ptop --pid <PID>` exercises the affected path
- [ ] <!-- additional scenario you covered -->

## Notes for the reviewer

<!-- Anything non-obvious: tricky tradeoffs, deferred work, follow-up issues
you opened. Skip if there's nothing to flag. -->

<!-- If this PR closes an issue, add `closes #NN` so it's auto-closed on
merge. -->
