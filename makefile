BIN_NAME = attack
GO_FILES = main.go tcp.go ip.go

all: build

build:
    @echo "Building..."
    go build -o $(BIN_NAME) $(GO_FILES)
    @echo "Building completed!"

clean:
    @echo "Removing binary files..."
    @rm -f *.o
    @echo "Removing completed!"

fclean: clean
    @rm -f $(BIN_NAME)

run:
    ./$(BIN_NAME) -$(host) -$(port)

.PHONY: all clcean fclean