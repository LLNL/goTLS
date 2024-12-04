BIN_NAME=gotls

all: build

build:
	go build -v -ldflags '-w' -o $(BIN_NAME)

man:
	cd rpm/man && go run main.go

bash:
	go run main.go completion bash > rpm/bash/completion.bash

clean:
	go clean
	rm -f $(BIN_NAME)
