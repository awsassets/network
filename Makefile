all: windows linux

windows:
	rsrc -manifest disembark.exe.manifest -ico disembark.ico
	GOOS=windows GOARCH=amd64 go build -v -ldflags "-X 'main.Version=$(shell git rev-parse HEAD)' -X 'main.Unix=$(shell date +%s)' -X 'main.User=$(shell git config --get user.name)'" -o bin/disembark.exe .

linux:
	GOOS=linux GOARCH=amd64 go build -v -ldflags "-X 'main.Version=$(shell git rev-parse HEAD)' -X 'main.Unix=$(shell date +%s)' -X 'main.User=$(shell git config --get user.name)'" -o bin/disembark .

lint:
	staticcheck ./...
	go vet ./...
	golangci-lint run

deps:
	go mod download
	go install github.com/akavel/rsrc@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
