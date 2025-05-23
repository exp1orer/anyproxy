.PHONY: all build clean run-gateway run-client certs

all: certs build

build:
	mkdir -p bin
	go build -o bin/anyproxy-gateway cmd/gateway/main.go
	go build -o bin/anyproxy-client cmd/client/main.go

certs:
	bash generate_certs.sh

run-gateway: build
	./bin/anyproxy-gateway --config configs/config.yaml

run-client: build
	./bin/anyproxy-client --config configs/config.yaml

clean:
	rm -rf bin 