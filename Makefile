CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinc -pthread -g
LDFLAGS = -lssl -lcrypto -pthread
SRC_DIR = src
INC_DIR = inc
OBJ_DIR = obj
BIN_DIR = .

SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Define targets for both the server and client
SERVER_OBJ = $(OBJ_DIR)/server.o $(OBJ_DIR)/sessionProtocol.o
CLIENT_OBJ = $(OBJ_DIR)/client.o $(OBJ_DIR)/sessionProtocol.o

all: $(BIN_DIR)/server $(BIN_DIR)/client

$(BIN_DIR)/server: $(SERVER_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

$(BIN_DIR)/client: $(CLIENT_OBJ)
	$(CC) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $@

.PHONY: clean

clean:
	rm -rf $(BIN_DIR)/server $(BIN_DIR)/client $(OBJ_DIR)
