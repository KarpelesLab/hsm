#!/bin/make
GOROOT:=$(shell PATH="/pkg/main/dev-lang.go/bin:$$PATH" go env GOROOT)
GOPATH:=$(shell $(GOROOT)/bin/go env GOPATH)

export GO111MODULE=on

all:
	$(GOPATH)/bin/goimports -w -l .
	$(GOROOT)/bin/go build -v
