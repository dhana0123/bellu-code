package seek

// Allocate returns the slot count per unit, in Plan order. have[i] is the number
// of candidates unit i has after the cutoff.
//
//  1. m is the number of units with have > 0. If m == 0, every count is zero.
//  2. If m > topK, the first topK units with candidates get 1 slot each.
//  3. Otherwise each unit with candidates gets floor(topK/m) slots, and the
//     first topK mod m of them (Plan order) get one more.
//  4. Each quota is capped by have[i]. Freed slots go out one at a time,
//     cycling in Plan order over units that still have unplaced candidates.
//
// The result has the same length as have, and have is not modified.
func Allocate(topK int, have []int) []int {
	out := make([]int, len(have))
	if topK <= 0 {
		return out
	}
	m := 0
	for _, n := range have {
		if n > 0 {
			m++
		}
	}
	if m == 0 {
		return out
	}

	base, extra := topK/m, topK%m
	if m > topK {
		base, extra = 1, 0
	}
	placed, seen := 0, 0
	for i, n := range have {
		if n <= 0 {
			continue
		}
		if m > topK && seen >= topK {
			break
		}
		quota := base
		if seen < extra {
			quota++
		}
		seen++
		out[i] = min(quota, n)
		placed += out[i]
	}

	// Reassign slots that capped units could not fill.
	for placed < topK {
		progressed := false
		for i, n := range have {
			if placed >= topK {
				break
			}
			if out[i] < n {
				out[i]++
				placed++
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	return out
}
