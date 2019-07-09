GOCMD=go

build: fmt test lint
	$(GOCMD) build -o bin/dcoscertstrap

test:
	$(GOCMD) test -v github.com/jr0d/dcoscertstrap/tests/gen

lint:
	golint -set_exit_status ./...

fmt:
	$(GOCMD) fmt ./...

all: fmt test lint build

