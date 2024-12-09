# GoodbyeDPI Go Implementation

## IPTables Setup

### Initialize (redirect traffic to NFQUEUE)

```bash
# Redirect outgoing HTTP traffic to queue 0
sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0

# Redirect incoming HTTP traffic to queue 0
sudo iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0
```

### List Rules

```bash
# Show all current iptables rules
sudo iptables -L -v -n
```

### Reset/Clear Rules

```bash
# Delete specific rules
sudo iptables -D OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
sudo iptables -D INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0

# Or flush all rules (use with caution)
sudo iptables -F
```

Note: The program requires root privileges to access NFQUEUE and send raw packets.
