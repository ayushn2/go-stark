build:
	@go build -o bin/go-snark main.go

# test:
# 	@go test -v ./...
# 	@go test -v ./snark

test:
	@go test -v ./stark

run: build
	@./bin/go-stark