# Makefile for the myproxy server
CC = gcc
CFLAGS =  -I/opt/homebrew/opt/openssl@3/include -pthread
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

# Define the source and binary directories
SRCDIR = ./src
BINDIR = ./bin

# Target executable name
TARGET = myproxy

# Default target
all: $(BINDIR)/$(TARGET)

$(BINDIR)/$(TARGET): $(SRCDIR)/$(TARGET).c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	ln -sf $(BINDIR)/$(TARGET) $(TARGET)

clean:
	rm -f $(BINDIR)/$(TARGET) $(TARGET)