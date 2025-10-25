# DSA-ASSIGNMENT_2
My Data Structures Assignment 2 (NETWORK MONITORING)

# Network Packet Monitor System

## GitHub Repository

Repository Link: [https://github.com/Ubaidcode11/DSA-ASSIGNMENT_2]

A Linux-based network packet capture, analysis, filtering, and replay system implemented using custom Stack and Queue data structures.

## Table of Contents
- [Overview]
- [Features]
- [Installation]
- [Usage]
- [Program Options]
- [Example Workflow]


## Overview

This program captures network packets in real-time, dissects protocol layers, filters packets based on IP addresses, and replays them with automatic retry mechanisms. It demonstrates practical implementation of data structures (Stack and Queue) in a networking context.

**Key Technologies:**
- Raw socket programming (Linux)
- Custom Stack implementation for protocol layer parsing
- Custom Queue implementation for packet management
- Protocol dissection: Ethernet, IPv4, IPv6, TCP, UDP

## Features

- Real-time Packet Capture - Live display of captured network packets
- Protocol Layer Analysis - Parse and display 5 protocol layers
- IP-based Filtering - Filter packets by source/destination IP
- Packet Replay - Replay filtered packets with retry mechanism
- Error Handling - Automatic retry queue for failed packets
- Statistics Dashboard - View system statistics and queue status
- Automated Testing - Complete test suite to validate all functionalities

## Installation

### Step 1: Download or Clone the Repository

```bash
# Using Git
git clone https://github.com/Ubaidcode11/DSA-ASSIGNMENT_2
cd network-packet-monitor

# Or download and extract the ZIP file
unzip network-packet-monitor.zip
cd network-packet-monitor


### Step 2: Compile the Program

```bash
# Compile with C++11 standard
g++ -o network_monitor network_monitor.cpp -std=c++11

# Verify compilation success
ls -lh network_monitor

Expected output:
-rwxr-xr-x 1 user user 45K Oct 25 10:30 network_monitor

## Usage

### Running the Program

```bash
# Run the program with sudo privileges (REQUIRED)
sudo ./network_monitor
```

**Important Notes:**
- Root/sudo privileges are mandatory for raw socket access
- The program will exit with an error if not run as root
- Default network interface is `enp0s3`

### Checking Your Network Interface

```bash
# List all network interfaces
ip link show

# Common interface names:
# - enp0s3 (VirtualBox VMs)
# - eth0 (Traditional Ethernet)
# - wlan0 (Wireless)
# - ens33 (VMware VMs)
```

If your interface is different, you may need to adjust the code accordingly.


## Program Options

When you run the program, you'll see this menu:

══════════════════════════════════════════════════════════════════
              NETWORK PACKET MONITORING SYSTEM                    
══════════════════════════════════════════════════════════════════

  [1] Start Packet Capture Session
  [2] View Captured Packets
  [3] Analyze Protocol Layers
  [4] Apply IP Address Filter
  [5] View Filtered Results
  [6] Execute Packet Replay
  [7] Check Retry Queue
  [8] Display System Statistics
  [9] Run Complete Test Suite
  [0] Exit Program
```

### Option Details

#### [1] Start Packet Capture Session
Captures network packets in real-time. You will be prompted to enter the duration in seconds (default is 60 seconds).

**Example:**
```bash
Select option: 1
Enter capture duration (seconds, default=60): 30

>> Initiating packet capture session
>> Duration: 30 seconds
>> Interface: enp0s3

[PKT #1] 74B | 192.168.1.100 → 8.8.8.8
[PKT #2] 1234B | 192.168.1.100 → 192.168.1.1
[PKT #3] 567B | 10.0.0.5 → 10.0.0.1


>> Capture session terminated
>> Total packets captured: 45
```

#### [2] View Captured Packets
Displays all packets currently stored in the main queue. Shows packet ID, timestamp, source/destination IPs, and packet size.

**Example Output:**
```
┌────────────────────────────────────────────────────────────────┐
│                    PACKET INVENTORY                            │
└────────────────────────────────────────────────────────────────┘

  [#1] Time: 1698234567 | Route: 192.168.1.100 → 8.8.8.8 | Size: 74B
  [#2] Time: 1698234568 | Route: 192.168.1.100 → 192.168.1.1 | Size: 1234B
  [#3] Time: 1698234569 | Route: 10.0.0.5 → 10.0.0.1 | Size: 567B

>> Total entries: 3 packets
```

#### [3] Analyze Protocol Layers
Parses each captured packet and displays its protocol layer structure. Uses a custom Stack to dissect layers from Ethernet down to TCP/UDP.

**Example Output:**
```
┌────────────────────────────────────────────────────────────────┐
│                PROTOCOL LAYER ANALYSIS                         │
└────────────────────────────────────────────────────────────────┘

  Packet #1 Breakdown:
  ├─ Path: 192.168.1.100 → 8.8.8.8
  ├─ Size: 74 bytes
  └─ Layer Structure:
      ├─ Layer 1: Ethernet
      ├─ Layer 2: IPv4
      └─ Layer 3: UDP

  Packet #2 Breakdown:
  ├─ Path: 192.168.1.100 → 192.168.1.1
  ├─ Size: 1234 bytes
  └─ Layer Structure:
      ├─ Layer 1: Ethernet
      ├─ Layer 2: IPv4
      └─ Layer 3: TCP

>> Analysis complete: 2 packets processed
```

#### [4] Apply IP Address Filter
Filters packets based on source and destination IP addresses. Supports bidirectional matching (finds packets going both directions between two IPs).

**Example:**
```bash
Select option: 4
Enter source IP address: 192.168.1.100
Enter destination IP address: 192.168.1.1

┌────────────────────────────────────────────────────────────────┐
│                    PACKET FILTERING                            │
└────────────────────────────────────────────────────────────────┘

>> Filter Criteria:
   Source: 192.168.1.100
   Destination: 192.168.1.1

  [MATCH] Packet #2 | Estimated delay: 1.234ms
  [MATCH] Packet #5 | Estimated delay: 0.890ms
  [SKIP] Packet #8 exceeds size limit (1800B)

>> Filtering results: 2 packets matched criteria
```

**Delay Calculation:** Delay (milliseconds) = Packet Size (bytes) / 1000

#### [5] View Filtered Results
Displays all packets that matched the filter criteria, showing their calculated delays and IP addresses.

**Example Output:**
```
┌────────────────────────────────────────────────────────────────┐
│                  FILTERED PACKET LIST                          │
└────────────────────────────────────────────────────────────────┘

  [#2] Delay: 1.234ms | 192.168.1.100 ↔ 192.168.1.1
  [#5] Delay: 0.890ms | 192.168.1.1 ↔ 192.168.1.100

>> Total filtered: 2 packets
```

#### [6] Execute Packet Replay
Attempts to replay all filtered packets. Each packet gets up to 3 attempts (1 initial + 2 retries). Failed packets are moved to the retry queue.

**Example Output:**
```
┌────────────────────────────────────────────────────────────────┐
│                    PACKET REPLAY                               │
└────────────────────────────────────────────────────────────────┘

  Replaying packet #2:
    Attempt 1/3 ... [SUCCESS]

  Replaying packet #5:
    Attempt 1/3 ... [FAILED]
    Attempt 2/3 ... [FAILED]
    Attempt 3/3 ... [SUCCESS]

>> Replay summary:
   Successful: 2 packets
   Failed: 0 packets (moved to retry queue)
```

#### [7] Check Retry Queue
Shows all packets that failed during replay and are queued for potential retry.

**Example Output:**
```
┌────────────────────────────────────────────────────────────────┐
│                    RETRY QUEUE STATUS                          │
└────────────────────────────────────────────────────────────────┘

  [#8] Attempts: 1 | 192.168.1.100 → 192.168.1.1 | 1800B
  [#12] Attempts: 2 | 10.0.0.5 → 10.0.0.1 | 2000B

>> Packets in retry queue: 2
```

#### [8] Display System Statistics
Shows the current status of all queues and total packet counts.

**Example Output:**
```
┌────────────────────────────────────────────────────────────────┐
│                   SYSTEM STATISTICS                            │
└────────────────────────────────────────────────────────────────┘

  Main Queue ............... 45 packets
  Filtered Queue ........... 2 packets
  Retry Queue .............. 2 packets
  Total Packets Captured ... 45
```

#### [9] Run Complete Test Suite
Runs an automated demonstration of all system features in sequence:
1. Captures packets for 60 seconds
2. Displays packet inventory
3. Analyzes protocol layers
4. Applies IP filter (using default IPs: 192.168.1.100 ↔ 192.168.1.1)
5. Shows filtered packets
6. Executes packet replay
7. Displays retry queue
8. Shows final statistics

This is ideal for testing and demonstrating the complete system functionality.

#### [0] Exit Program
Cleanly exits the program and releases all resources.

---

## Example Workflow

Here's a typical usage scenario:

```bash
# Step 1: Start the program
sudo ./network_monitor

# Step 2: Capture packets for 30 seconds
Select option: 1
Enter capture duration (seconds, default=60): 30
# Wait for capture to complete...

# Step 3: View what was captured
Select option: 2
# Review the packet list

# Step 4: Analyze protocol layers
Select option: 3
# See the layer breakdown for each packet

# Step 5: Filter packets by IP address
Select option: 4
Enter source IP address: 192.168.1.100
Enter destination IP address: 192.168.1.1

# Step 6: View filtered results
Select option: 5
# Review matched packets and their delays

# Step 7: Replay the filtered packets
Select option: 6
# Watch the replay attempts

# Step 8: Check if any packets failed
Select option: 7
# View the retry queue

# Step 9: View overall statistics
Select option: 8
# See summary of all queues

# Step 10: Exit the program
Select option: 0
```

---

## Quick Test

To quickly test all functionalities without manual intervention:

```bash
sudo ./network_monitor

# Select option 9 for automated test suite
Select option: 9

# The program will run all tests automatically
# and display results for each component
```

---

## Compilation Commands

```bash
# Basic compilation
g++ -o network_monitor network_monitor.cpp -std=c++11

# With optimization
g++ -o network_monitor network_monitor.cpp -std=c++11 -O2

# With all warnings
g++ -o network_monitor network_monitor.cpp -std=c++11 -Wall
```

---

## Important Notes

1. **Root Privileges Required**: The program MUST be run with sudo or as root user
2. **Network Interface**: Default is enp0s3 - verify your interface name before running
3. **Active Network**: Ensure network traffic is present for packet capture
4. **Linux Only**: This program is designed for Linux systems only
5. **Educational Purpose**: This is a learning tool, not for production use

---

## Supported Protocols

The program can parse the following protocol layers:

| Protocol | OSI Layer | Description |
|----------|-----------|-------------|
| Ethernet | Layer 2 | Data link layer framing |
| IPv4 | Layer 3 | Internet Protocol version 4 |
| IPv6 | Layer 3 | Internet Protocol version 6 |
| TCP | Layer 4 | Transmission Control Protocol |
| UDP | Layer 4 | User Datagram Protocol |

---

## Data Structures

**Custom Stack (LIFO)**
- Used for protocol layer dissection
- Allows parsing from outer to inner layers
- Operations: push, pop, peek

**Custom Queue (FIFO)**
- Used for packet management
- Three separate queues: Main, Filtered, Retry
- Operations: enqueue, dequeue, peek
sssss
