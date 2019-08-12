PROJECT_NAME := dcos-bootstrap-ca
PKG := github.com/mesosphere/$(PROJECT_NAME)
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)
GO_FILES := $(shell find . -name '*.go' | grep -v /vendor/ | grep -v _test.go)

.PHONY: all fmt build clean lint

build: fmt test lint
	@go build -o bin/$(PROJECT_NAME)

test:
	@go test ./...

lint:
	@golint -set_exit_status ./...

fmt:
	@go fmt ./...

clean:
	@rm -f bin/$(PROJECT_NAME)

all: fmt test lint build

