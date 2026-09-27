# sni-scanner — convenience targets (optional; plain `go` commands work too).
GO ?= go

.PHONY: build test vet run-demo run-demo-json run-demo-xray clean fmt

build:
	$(GO) build -o bin/sni-scanner ./cmd/sni-scanner

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

run-demo:
	$(GO) run ./cmd/sni-scanner --demo --output table

run-demo-json:
	$(GO) run ./cmd/sni-scanner --demo --output json

run-demo-xray:
	$(GO) run ./cmd/sni-scanner --demo --output xray-snippet

fmt:
	$(GO) fmt ./...

clean:
	rm -rf bin runs
