# Root Makefile for bellud.
export PATH := $(PATH):/usr/local/go/bin
BELLUD_DIR := services/bellud
.PHONY: bellud
# Same output as the turbo build task: services/bellud/dist/bellud
bellud:
	cd $(BELLUD_DIR) && go build -trimpath -o dist/bellud ./cmd/bellud
