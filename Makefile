build:
	CGO_ENABLED=0 go build -o bin/tunnel ebpf-play

generate:
	go generate
