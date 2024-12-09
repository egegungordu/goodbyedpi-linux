# GoodbyeDPI Go Implementation

## IPTables Setup

### Initialize (redirect traffic to NFQUEUE)

```bash
# Redirect outgoing HTTP traffic to queue 0 (except our marked packets)
sudo iptables -A OUTPUT -p tcp --dport 80 -m mark ! --mark 1 -j NFQUEUE --queue-num 0

# Redirect incoming HTTP traffic to queue 0
sudo iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0

# Redirect DNS traffic (both UDP and TCP)
sudo iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -p udp --dport 1253 -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -p udp --sport 1253 -j NFQUEUE --queue-num 0
```

### List Rules

```bash
# Show all current iptables rules
sudo iptables -L -v -n
```

### Reset/Clear Rules

```bash
# Delete specific rules
sudo iptables -D OUTPUT -p tcp --dport 80 -m mark ! --mark 1 -j NFQUEUE --queue-num 0
sudo iptables -D INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0
sudo iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
sudo iptables -D INPUT -p udp --sport 53 -j NFQUEUE --queue-num 0
sudo iptables -D OUTPUT -p udp --dport 1253 -j NFQUEUE --queue-num 0
sudo iptables -D INPUT -p udp --sport 1253 -j NFQUEUE --queue-num 0

# Or flush all rules (use with caution)
sudo iptables -F
```

Note: The program requires root privileges to access NFQUEUE and send raw packets.

## Requirements

- Go 1.19 or later
- Linux system with NFQUEUE support
- Root privileges for packet manipulation

## Building

```bash
go build -o goodbyedpi-linux ./cmd/goodbyedpi
```

## Credits

This is a Go port of the original GoodbyeDPI project. Thanks to:

- @basil00 for [WinDivert](https://github.com/basil00/Divert)
- [BlockCheck](https://github.com/ValdikSS/blockcheck) contributors
- Original GoodbyeDPI developers

## Related Projects

For other DPI circumvention tools, check out:

- [Original GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)
- [Green Tunnel](https://github.com/SadeghHayeri/GreenTunnel)
- [PowerTunnel](https://github.com/krlvm/PowerTunnel)
- And others listed in the main project README

## License

This project is licensed under the same terms as the original GoodbyeDPI project.
