# Reproducing the development environment

This repository uses Go modules. Production dependencies are Go's standard
library; test dependency versions and checksums are pinned by go.mod and go.sum.

Verified on Ubuntu under WSL2 with Go 1.24.9 (linux/amd64), GCC 15.2.0,
Node.js 22.22.1 and Codex CLI 0.160.0.

Prepare test dependencies before entering a network-restricted sandbox:

```sh
go mod download
```

For offline tests, use a writable compilation cache. The module cache must
already contain the versions pinned by go.mod/go.sum:

```sh
export GOCACHE=/tmp/userfeedback-task004-gocache
export GOPROXY=off
export GOSUMDB=off
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
```

The tests use local inputs and do not require external services or listening
sockets. Race tests require a working C compiler. A fresh machine needs the
Go toolchain and the pinned test modules before offline execution.
