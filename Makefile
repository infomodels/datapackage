GIT_SHA := $(shell git log -1 --pretty=format:"%h")

install:
	go get github.com/blang/semver
	go get github.com/chop-dbhi/data-models-service/client
	go get golang.org/x/crypto/openpgp

test-install: install
	go get golang.org/x/tools/cmd/cover

build-install:
	go get github.com/mitchellh/gox

test:
	go test -cover ./...

bench:
	go test -run=none -bench=. ./...

build:
	go build \
		-ldflags "-X packer.progBuild='$(GIT_SHA)'" \
		-o $(GOPATH)/bin/data-models-packer ./cmd/packer

# Build and tag binaries for each OS and architecture.
dist-build:
	mkdir -p dist

	gox -output="dist/{{.OS}}-{{.Arch}}/data-models-packer" \
		-ldflags "-X packer.progBuild='$(GIT_SHA)'" \
		-os="linux windows darwin" \
		-arch="amd64" \
		./cmd/packer > /dev/null

dist-zip:
	cd dist && zip data-models-packer-linux-amd64.zip linux-amd64/*
	cd dist && zip data-models-packer-windows-amd64.zip windows-amd64/*
	cd dist && zip data-models-packer-darwin-amd64.zip darwin-amd64/*

dist: dist-build dist-zip


.PHONY: test build dist-build dist
