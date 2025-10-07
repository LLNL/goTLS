BIN_DIR=bin

ifeq ($(GOOS), windows)
    BIN_NAME=gotls.exe
    BIN_INSTALLER_NAME=gotls-installer.exe
    BUILD_VAR ?= CGO_ENABLED=1 CC="x86_64-w64-mingw32-gcc --sysroot=/usr/x86_64-w64-mingw32/sys-root"
else
    BIN_NAME=gotls
    BUILD_VAR ?= CGO_ENABLED=1
endif

all: build

vendor:
	go mod vendor

build: vendor
	$(BUILD_VAR) go build -v -mod=vendor -ldflags '-w -s -extldflags "-fno-PIC -static"' -buildmode pie -tags 'osusergo netgo static_build' -o $(BIN_DIR)/$(BIN_NAME)

man: vendor
	cd rpm/man && go run main.go

bash: vendor
	go run main.go completion bash > rpm/bash/completion.bash

wininstaller: build
	makensis wininstaller.nsi && chmod +x $(BIN_DIR)/$(BIN_INSTALLER_NAME)

clean:
	go clean
	rm -f $(BIN_DIR)/*

.PHONY: vendor build clean
