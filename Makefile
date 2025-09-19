BIN_DIR=bin

ifeq ($(GOOS), windows)
    BIN_NAME=gotls.exe
else
    BIN_NAME=gotls
endif

all: build

vendor:
	go mod vendor

build: vendor
	go build -v -mod=vendor -ldflags '-w' -o $(BIN_NAME)

man: vendor
	cd rpm/man && go run main.go

bash: vendor
	go run main.go completion bash > rpm/bash/completion.bash

wininstaller: build
	makensis wininstaller.nsi && chmod +x $(BIN_NAME)-installer.exe

clean:
	go clean
	rm -f $(BIN_NAME)
	rm -f $(BIN_NAME)-installer.exe

.PHONY: vendor build clean
