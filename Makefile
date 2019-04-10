BIN_NAME=gotls

all: build

build:
	go build -v -ldflags '-w' -o $(BIN_NAME)

man:
	cd rpm/man && go run main.go

clean:
	go clean
	rm -f $(BIN_NAME)
