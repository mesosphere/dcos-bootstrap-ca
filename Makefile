PROJECT_NAME := "dcoscertstrap"
PKG := "github.com/jr0d/$(PROJECT_NAME)"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)
GO_FILES := $(shell find . -name '*.go' | grep -v /vendor/ | grep -v _test.go)

.PHONY: all fmt build clean lint

build: fmt test lint
	@go build -o bin/dcoscertstrap

test:
	@go test ./...

lint:
	@golint -set_exit_status ./...

fmt:
	@go fmt ./...

clean:
	@rm -f bin/$(PROJECT_NAME)

all: fmt test lint build

