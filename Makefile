# DNS Server - Makefile
# C++ DNS Server Implementation

CXX = g++
CXXFLAGS = -std=c++23 -Wall -Wextra -O2
LDFLAGS =

# Directories
SRC_DIR = src
BUILD_DIR = build

# Source files
SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

# Target executable
TARGET = $(BUILD_DIR)/dns-server

# Default target
all: $(TARGET)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Link
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Run the server
run: $(TARGET)
	./$(TARGET)

# Run with resolver
run-resolver: $(TARGET)
	./$(TARGET) --resolver 8.8.8.8:53

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Rebuild
rebuild: clean all

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: clean all

.PHONY: all run run-resolver clean rebuild debug
