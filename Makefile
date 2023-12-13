run:
	go run cmd/tcp-proxy/main.go -color

build-bin:
	mkdir -p target
	go build -ldflags="-w -s" -o target/tcp-proxy cmd/tcp-proxy/main.go
