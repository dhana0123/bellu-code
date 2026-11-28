package seek

import (
	"reflect"
	"testing"
)

// Requirements 6.5, 6.9, 12.1: Top_K allocation across plan units.
func TestAllocate(t *testing.T) {
	tests := []struct {
		name string
		topK int
		have []int
		want []int
	}{
		{"even split", 4, []int{5, 5}, []int{2, 2}},
		{"even split three units", 6, []int{9, 9, 9}, []int{2, 2, 2}},
		{"remainder goes to earlier units", 4, []int{5, 5, 5}, []int{2, 1, 1}},
		{"remainder of two goes to first two", 5, []int{5, 5, 5}, []int{2, 2, 1}},
		{"more units than topK: first topK units get one", 2, []int{3, 3, 3, 3}, []int{1, 1, 0, 0}},
		{"more units than topK skips units without candidates", 2, []int{0, 3, 3, 3}, []int{0, 1, 1, 0}},
		{"unused slots reassigned to later unit", 4, []int{1, 9}, []int{1, 3}},
		{"unused slots reassigned to earlier unit", 4, []int{9, 1}, []int{3, 1}},
		{"reassignment cycles in plan order", 7, []int{1, 9, 9}, []int{1, 3, 3}},
		{"unit without candidates is skipped", 4, []int{0, 5, 5}, []int{0, 2, 2}},
		{"all candidates fit under quota", 10, []int{1, 2, 3}, []int{1, 2, 3}},
		{"no candidates anywhere", 4, []int{0, 0, 0}, []int{0, 0, 0}},
		{"empty plan", 4, []int{}, []int{}},
		{"single unit capped by topK", 4, []int{9}, []int{4}},
		{"single unit capped by have", 4, []int{2}, []int{2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Allocate(tt.topK, tt.have)
			if len(got) != len(tt.have) {
				t.Fatalf("len = %d, want %d", len(got), len(tt.have))
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Allocate(%d, %v) = %v, want %v", tt.topK, tt.have, got, tt.want)
			}
		})
	}
}

func TestAllocateSumAndBounds(t *testing.T) {
	haves := [][]int{
		{}, {0}, {0, 0}, {1}, {5, 5}, {1, 9}, {9, 1, 0, 4}, {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		{50, 0, 1, 3, 7},
	}
	for topK := MinTopK; topK <= MaxTopK; topK++ {
		for _, have := range haves {
			got := Allocate(topK, have)
			sum, total := 0, 0
			for i, n := range got {
				if n < 0 || n > have[i] {
					t.Fatalf("Allocate(%d, %v)[%d] = %d outside [0,%d]", topK, have, i, n, have[i])
				}
				sum += n
				total += have[i]
			}
			if want := min(topK, total); sum != want {
				t.Fatalf("Allocate(%d, %v) = %v, sum %d, want %d", topK, have, got, sum, want)
			}
		}
	}
}

func TestAllocateDoesNotModifyInput(t *testing.T) {
	have := []int{3, 0, 5}
	Allocate(4, have)
	if !reflect.DeepEqual(have, []int{3, 0, 5}) {
		t.Fatalf("have was modified: %v", have)
	}
}
