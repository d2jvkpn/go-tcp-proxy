run:
	go run cmd/tcp-proxy/main.go -color

build-bin:
	mkdir -p target
	# -ldflags="-w -s"
	GOOS=linux GOARCH=amd64 go build -o target/tcp-proxy cmd/tcp-proxy/main.go
	GOOS=windows GOARCH=amd64 go build -o target/tcp-proxy.exe cmd/tcp-proxy/main.go
