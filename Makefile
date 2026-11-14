# One entry point: `make check` runs everything CI runs.
export GOWORK := off
export GOTOOLCHAIN := go1.27.4

.PHONY: check fmt-check vet test

check: fmt-check vet test

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run gofmt -w ." && exit 1)

vet:
	go vet ./...

test:
	go test -race -count=1 ./...
