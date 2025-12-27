# DNS Server

A lightweight DNS server implementation written in C++23 that can parse and respond to DNS queries, with optional upstream resolver forwarding support.

## Features

- **DNS Query Parsing**: Parses incoming DNS packets including headers, questions, and answers
- **DNS Name Compression**: Supports RFC 1035 message compression for domain names
- **Query Response**: Creates properly formatted DNS response packets
- **Resolver Forwarding**: Can forward queries to an upstream DNS resolver (e.g., 8.8.8.8)
- **Multiple Questions**: Handles DNS packets with multiple questions
- **UDP Protocol**: Listens on UDP port 2053

## Building

Requirements:
- GCC with C++23 support (g++ 11+)
- Make

```bash
# Build the project
make

# Build with debug symbols
make debug

# Clean build artifacts
make clean

# Rebuild from scratch
make rebuild
```

## Usage

### Basic Mode (Default Responses)

Run the server without a resolver to return default responses (8.8.8.8 for all A record queries):

```bash
./run.sh
# or
make run
```

### Resolver Mode

Forward queries to an upstream DNS resolver:

```bash
./run.sh --resolver 8.8.8.8:53
# or
make run-resolver
```

You can specify any resolver IP and port:

```bash
./run.sh --resolver 1.1.1.1:53
```

### Testing

Test the server using `dig`:

```bash
# Query for a domain
dig @127.0.0.1 -p 2053 google.com

# Query with specific record type
dig @127.0.0.1 -p 2053 google.com A
```

## Project Structure

```
.
├── Makefile           # Build configuration
├── README.md          # This file
├── run.sh             # Run script (builds if needed)
├── build/             # Build output directory (generated)
│   └── dns-server     # Compiled executable
└── src/
    └── main.cpp       # Main source file
```

## How It Works

1. **Server Initialization**: Creates a UDP socket bound to port 2053
2. **Query Reception**: Receives DNS query packets from clients
3. **Packet Parsing**: Parses the DNS header, questions, and extracts domain names
4. **Response Generation**:
   - **Without resolver**: Returns a default A record (8.8.8.8)
   - **With resolver**: Forwards each question to the upstream resolver and collects answers
5. **Response Sending**: Constructs and sends the DNS response packet back to the client

## DNS Packet Format

The implementation follows the DNS packet format as defined in RFC 1035:

- **Header** (12 bytes): ID, Flags, Question Count, Answer Count, etc.
- **Question Section**: Domain name, Query Type, Query Class
- **Answer Section**: Domain name, Type, Class, TTL, Data Length, Data
