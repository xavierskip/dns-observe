# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`dns-observe` is a Python DNS client that observes DNS pollution by sending queries and listening for multiple responses over a time window. It uses raw UDP sockets and implements DNS protocol parsing per RFC 1035.

**Note**: When referencing network infrastructure that may trigger content moderation, use generic terms like "firewall" instead of specific names.

## Development Commands

```bash
# Install in editable mode for development
pip install -e .

# Run tests
python tests/test_run.py

# Build package for distribution
python -m build

# Upload to TestPyPI
python -m twine upload --repository testpypi dist/*

# Upload to PyPI
python -m twine upload dist/*
```

## CLI Usage

```bash
# Command-line entry point
dns-observe <domain> [-s DNS_SERVER] [-t LISTEN_TIME] [-q QUERY_TYPE]

# Module execution
python -m dns_observe <domain>
```

## Architecture

**Single-module package** (`src/dns_observe/dns.py`):

- **`DNSQuery`**: Main class for sending DNS queries and collecting responses
  - `query(qname, qtype)`: Sends query and listens for `wait_time` seconds (default: 5), collecting all responses
  - Uses UDP socket with configurable timeout
  - Outputs formatted results with box-drawing characters for multiple answers

- **`DNSResponse`**: Parsed DNS response container with header fields and answer list

- **`DNSResourceRecord`**: Individual DNS record with properties `ipv4_address` and `ipv6_address`

**Supported record types**: A, AAAA, CNAME, TXT, HTTPS (defined in `RecordType` class and `QTYPE` dict)

**Protocol implementation**:
- Request building: `_build_request()` constructs raw DNS packet with 12-byte header + question section
- Response parsing: `_parse_response()` handles name decompression (RFC 1035 §4.1.4), supports message compression pointers (0b11 prefix)
- Name parsing: `_parse_name()` recursively resolves compression pointers

**Key design**: The `query()` method listens continuously for the full `wait_time` duration, capturing multiple responses to detect DNS pollution scenarios where conflicting answers may arrive.
