BIN_NAME=gotls

all: build

build:
	go build -o $(BIN_NAME) -v

clean:
	go clean
	rm -f $(BIN_NAME)
