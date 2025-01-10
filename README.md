# SSH Known Hosts Checker

A Go tool for parsing SSH known_hosts files and attempting SSH connections.

## Features

- Parses both ~/.ssh/known_hosts and ~/.ssh/known_hosts.old files
- Supports both password and key-based authentication
- Multi-threaded connection attempts
- Detailed success/failure reporting

## Usage

```bash
# Build the program
go build

# Run with password authentication
./ssh-known-hosts-checker -user username -password yourpassword

# Run with key-based authentication
./ssh-known-hosts-checker -user username -key /path/to/private/key

# Optional: Specify custom port (default: 22)
./ssh-known-hosts-checker -user username -password yourpassword -port 2222
```

## Requirements

- Go 1.18 or later
- Access to SSH known_hosts files
