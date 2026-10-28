BIN := crowdsec-fleet-agent
VERSION ?= 0.2.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test release clean

build:
	go build -ldflags="$(LDFLAGS)" -o bin/$(BIN) .

test:
	go vet ./...
	go test ./...

release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BIN)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BIN)-linux-arm64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BIN)-linux-armv7 .

clean:
	rm -rf bin dist
