package tui

import (
	"sort"

	"github.com/trentas/ptop/pkg/collector"
)

// The CPU attribution panel's state (#125): a rolling window of the profiles
// the collector publishes, folded into one ranking.
//
// ─── Why the TUI aggregates instead of showing what arrived ─────────────────
//
// The collector publishes one profile a second, which is the right cadence for
// a stream a consumer will diff offline. It is the wrong thing to render at
// 5fps. At the default 99Hz a target using 2.5% of a core contributes about
// two and a half samples to a one-second window, so a top-N built from it is
// two or three samples reshuffling on every frame — the shot noise #108 was
// about, turned into a slot machine, and worse than the stream version because
// a human pattern-matches on a flickering list and believes it.
//
// Thirty seconds of profiles is ~75 samples for that same target and ~3000 for
// one using a whole core. The window is what makes the panel readable; the
// sample count, shown beside it, is what lets the reader discount it anyway.
const cpuSiteWindowSeconds = 30

// cpuSiteWindow holds the profiles inside the window, oldest first.
type cpuSiteWindow struct {
	profiles []collector.CPUProfile
}

// add appends a profile and drops whatever has aged out. Bounded by count
// rather than by timestamp arithmetic because the collector's cadence is its
// own: one profile carries the window it covers, and dropping by count keeps
// the panel's window proportional to that cadence whatever it is.
func (w *cpuSiteWindow) add(p collector.CPUProfile) {
	w.profiles = append(w.profiles, p)
	if n := len(w.profiles); n > cpuSiteWindowSeconds {
		w.profiles = append(w.profiles[:0], w.profiles[n-cpuSiteWindowSeconds:]...)
	}
}

// cpuSiteSummary is the folded window: what the panel renders.
type cpuSiteSummary struct {
	Sites      []collector.CPUSite
	Total      uint64  // samples that caught the target on-CPU, unresolved included
	Unresolved uint64  // samples with no usable leaf
	WindowMs   uint64  // wall time the fold covers
	RateHz     float64 // achieved per-CPU sampling rate, sample-weighted mean
	Requested  float64 // the rate that was asked for

	// Omitted is the samples the COLLECTOR's own top-N cut left out, summed
	// over the window, and TotalSites the largest number of distinct functions
	// any one profile saw.
	//
	// Carried so the panel can say the list is a selection rather than a
	// census. Without it a reader watching a function drop out cannot tell "it
	// stopped running" from "it stopped being in the top eight", and those call
	// for opposite responses — the same contract the heap axis publishes
	// omitted totals for (#109).
	Omitted    uint64
	TotalSites uint32
}

// Ranked reports whether there are enough samples for the ordering to mean
// anything.
//
// Below the floor the panel says so instead of showing a list. A share alone
// cannot be refused by the reader, and a top-N drawn from a dozen samples is an
// ordering of noise — with 30 samples the standard error on a 50% share is
// about nine points, enough to swap the first two rows at random. The floor is
// deliberately a blunt count and not a confidence interval: the panel's job is
// to refuse, not to quantify, and the count is printed either way so the reader
// can judge for themselves.
func (s cpuSiteSummary) Ranked() bool { return s.Total >= cpuSiteMinSamples }

const cpuSiteMinSamples = 100

// Truncated reports whether the collector's top-N cut anything, which is the
// only state in which a function's ABSENCE from this list does not mean it took
// no samples.
func (s cpuSiteSummary) Truncated() bool { return s.Omitted > 0 }

// BlindPct is the share of samples the axis could not name. Non-trivial values
// are surfaced: a panel ranking the 6% it could resolve, with no word about the
// 94% it could not, is the most confident way to be wrong.
func (s cpuSiteSummary) BlindPct() float64 {
	if s.Total == 0 {
		return 0
	}
	return float64(s.Unresolved) / float64(s.Total) * 100
}

// fold merges every profile in the window into one ranking.
//
// Sites are merged by collector.CPUSite.Key — the same rule the collector folds
// by, deliberately shared rather than reimplemented. Shares are recomputed
// against the window's own total, so they mean "of the CPU time seen in the last
// thirty seconds" rather than being an average of per-second percentages, which
// would weight a quiet second the same as a busy one.
//
// The identity fields come from the site with the most samples in the window,
// so Line stays the hottest line rather than whichever second happened to be
// last.
func (w cpuSiteWindow) fold() cpuSiteSummary {
	var out cpuSiteSummary
	type acc struct {
		site     collector.CPUSite
		dominant uint64
	}
	by := make(map[string]*acc, 16)
	order := make([]string, 0, 16)
	var firedWeighted float64

	for _, p := range w.profiles {
		out.Total += p.TotalSamples
		out.Unresolved += p.UnresolvedSamples
		out.WindowMs += p.WindowMs
		if p.RequestedRateHz > 0 {
			out.Requested = p.RequestedRateHz
		}
		// Sample-weighted, so a window in which the sampler barely ran does
		// not drag the reported rate down as if it had.
		firedWeighted += p.SampleRateHz * float64(p.WindowMs)
		out.Omitted += p.OmittedSamples
		if p.TotalSites > out.TotalSites {
			out.TotalSites = p.TotalSites
		}

		for _, s := range p.Sites {
			k := s.Key()
			a := by[k]
			if a == nil {
				by[k] = &acc{site: s, dominant: s.Samples}
				order = append(order, k)
				continue
			}
			total := a.site.Samples + s.Samples
			if s.Samples > a.dominant {
				a.site, a.dominant = s, s.Samples
			}
			a.site.Samples = total
		}
	}
	if out.WindowMs > 0 {
		out.RateHz = firedWeighted / float64(out.WindowMs)
	}

	out.Sites = make([]collector.CPUSite, 0, len(order))
	for _, k := range order {
		out.Sites = append(out.Sites, by[k].site)
	}
	sort.Slice(out.Sites, func(i, j int) bool {
		if out.Sites[i].Samples != out.Sites[j].Samples {
			return out.Sites[i].Samples > out.Sites[j].Samples
		}
		return out.Sites[i].Func < out.Sites[j].Func
	})
	for i := range out.Sites {
		out.Sites[i].SharePct = 0
		if out.Total > 0 {
			out.Sites[i].SharePct = float64(out.Sites[i].Samples) / float64(out.Total) * 100
		}
	}
	return out
}
