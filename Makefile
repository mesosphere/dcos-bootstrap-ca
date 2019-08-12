PROJECT_NAME := dcos-bootstrap-ca
STANDALONE_IMAGE := mesosphere/$(PROJECT_NAME)-standalone
VERSION := $(shell git describe --tags)
PKG := github.com/mesosphere/$(PROJECT_NAME)
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)
GO_FILES := $(shell find . -name '*.go' | grep -v /vendor/ | grep -v _test.go)

.PHONY: all fmt build clean lint standalone

build: fmt test lint
	@go build -o bin/$(PROJECT_NAME)
	GOOS=linux go build -o bin/$(PROJECT_NAME)-linux

test:
	@go test ./...

lint:
	@golint -set_exit_status ./...

fmt:
	@go fmt ./...

clean:
	@rm -f bin/$(PROJECT_NAME)*

all: fmt test lint build

docker/standalone/$(PROJECT_NAME): build
	cp bin/$(PROJECT_NAME)-linux docker/standalone/$(PROJECT_NAME)

standalone: docker/standalone/$(PROJECT_NAME)
	docker build -t $(STANDALONE_IMAGE):$(VERSION) -f docker/standalone/Dockerfile docker/standalone

standalone-push: standalone
	docker push $(STANDALONE_IMAGE):$(VERSION)
