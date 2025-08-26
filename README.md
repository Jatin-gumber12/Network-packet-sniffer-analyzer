# Network Packet Sniffer & Analyzer

## Overview
A lightweight packet sniffer and analyzer built with Python (Scapy) that captures network traffic, parses IP/TCP/UDP/ICMP headers, stores packet data (pcap/CSV) and provides a foundation for a Flask-based dashboard. Containerized with Docker and designed to be deployed on Kubernetes (Minikube/EKS/GKE/AKS).

## Features
- Capture live packets from a selected interface
- Decode Ethernet / IPv4 / TCP / UDP / ICMP
- Save captures to `.pcap` (Wireshark-compatible) and CSV summaries
- BPF filtering support (e.g., `tcp port 80`)
- Docker + Kubernetes ready

## System Requirements
- Ubuntu 20.04/22.04 (recommended)
- Python 3.8+
- Docker (for containerization)
- Minikube (optional, for local K8s)
- Git & GitHub account

## Quick Install (local, recommended)
```bash
# update OS
sudo apt update && sudo apt upgrade -y

# create project dir and virtualenv
python3 -m venv packet-sniffer-env
source packet-sniffer-env/bin/activate

# install dependencies
pip install -r requirements.txt
