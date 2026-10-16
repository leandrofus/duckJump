.PHONY: all build build-linux build-windows test clean

BINARY_NAME=duckjump-assist-ui

all: build

build:
	go build -o bin/$(BINARY_NAME) main.go

# Cross-compilation for Windows using MinGW or fyne-cross
build-windows:
	CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -ldflags -H=windowsgui -o bin/$(BINARY_NAME).exe main.go

# Build using docker container if host lacks X11/OpenGL development headers
docker-build-linux:
	docker run --rm -v $(CURDIR):/src -w /src ubuntu:24.04 bash -c "\
		apt-get update -qq && \
		apt-get install -y -qq golang ca-certificates libgl1-mesa-dev xorg-dev && \
		go build -o bin/$(BINARY_NAME) main.go"

test:
	go test -v ./...

clean:
	rm -rf bin/
