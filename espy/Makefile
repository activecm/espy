VERSION := $(shell git describe --abbrev=0 --tags)
EXACT_VERSION := $(shell git describe --always --long --dirty --tags)
PREFIX ?= /usr/local

LDFLAGS := -ldflags='-X github.com/activecm/espy/espy/config.Version=${VERSION} -X github.com/activecm/espy/espy/config.ExactVersion=${EXACT_VERSION}'

# go source files
SRC := $(shell find . -path ./vendor -prune -o -type f -name '*.go' -print)

.PHONY: espy
espy: $(SRC)
	go build ${LDFLAGS}