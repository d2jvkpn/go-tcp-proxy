build-bin:
	mkdir -p target
	go build -ldflags="-w -s" -o target/tcp-proxy cmd/tcp-proxy/main.go
