VERSION ?= 1.0.0
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build linux test vet run demo lab docker release clean

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o bin/asi ./cmd/asi

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/asi-linux-amd64 ./cmd/asi

test:
	go test ./...

vet:
	go vet ./...

run: build
	ASI_DATA_DIR=./data ./bin/asi serve

demo: build
	ASI_DATA_DIR=./data-demo ASI_DEMO=1 ./bin/asi serve

lab: build
	./bin/asi lab --prefix 127.0.1. --port-offset 8000

docker:
	docker compose build

# tarball for "scp + ./deploy/install.sh" deployment
release: linux
	tar czf asi-$(VERSION)-linux-amd64.tar.gz bin/asi-linux-amd64 deploy docs examples README.md

clean:
	rm -rf bin data data-demo asi-*.tar.gz
