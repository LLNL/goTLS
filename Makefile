BIN_NAME=gotls

all: build

build:
	go build -v -ldflags '-s -w' -o $(BIN_NAME)

clean:
	go clean
	rm -f $(BIN_NAME)
