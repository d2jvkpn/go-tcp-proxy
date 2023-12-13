run:
	go run cmd/tcp-proxy/main.go -color

build-bin:
	mkdir -p target
	# -ldflags="-w -s"
	go build -o target/tcp-proxy cmd/tcp-proxy/main.go
