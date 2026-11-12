# Root Makefile for bellud and the bellu-graph vendor sync.
export PATH := $(PATH):/usr/local/go/bin

BELLUD_DIR := services/bellud
SYNC_FLAGS ?=
COMMIT ?=

.PHONY: bellud sync-graph

# Same output as the turbo build task: services/bellud/dist/bellud
bellud:
	cd $(BELLUD_DIR) && go build -trimpath -o dist/bellud ./cmd/bellud

# Usage: make sync-graph COMMIT=<40-hex upstream Toise commit> [SYNC_FLAGS=-record]
sync-graph:
	@if [ -z "$(COMMIT)" ]; then \
		echo "error: COMMIT is required, e.g. make sync-graph COMMIT=<40-hex commit>" >&2; \
		exit 2; \
	fi
	script/sync-bellu-graph $(SYNC_FLAGS) $(COMMIT)
	cd $(BELLUD_DIR) && go test ./internal/bellugraph/pkg/emit -run TestFixtureV1 -update
