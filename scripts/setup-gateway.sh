#!/bin/bash
# =============================================================================
# VPN Gateway Setup Script
# =============================================================================
# This script configures a Linux server to act as a VPN gateway,
# allowing clients to route their internet traffic through the VPN.
#
# Usage:
#   sudo ./setup-gateway.sh enable eth0   # Enable gateway mode
#   sudo ./setup-gateway.sh disable eth0  # Disable gateway mode
#   sudo ./setup-gateway.sh status        # Show current status
# =============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

VPN_SUBNET="10.0.0.0/24"
TUN_IFACE="tun0"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

show_status() {
    echo "=== VPN Gateway Status ==="
    echo ""
    
    # IP forwarding
    IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
    if [ "$IP_FORWARD" = "1" ]; then
        echo -e "IP Forwarding: ${GREEN}ENABLED${NC}"
    else
        echo -e "IP Forwarding: ${RED}DISABLED${NC}"
    fi
    
    # NAT rules
    echo ""
    echo "NAT Rules (POSTROUTING):"
    iptables -t nat -L POSTROUTING -n -v 2>/dev/null || echo "  (unable to read)"
    
    echo ""
    echo "Forward Rules:"
    iptables -L FORWARD -n -v 2>/dev/null | head -10 || echo "  (unable to read)"
    
    # Network interfaces
    echo ""
    echo "Network Interfaces:"
    ip -br addr show
}

enable_gateway() {
    local EXT_IFACE=$1
    
    if [ -z "$EXT_IFACE" ]; then
        log_error "External interface required"
        echo "Usage: $0 enable <interface>"
        echo "Example: $0 enable eth0"
        echo ""
        echo "Available interfaces:"
        ip -br link show | grep -v "lo\|tun"
        exit 1
    fi
    
    # Verify interface exists
    if ! ip link show "$EXT_IFACE" &>/dev/null; then
        log_error "Interface $EXT_IFACE not found"
        exit 1
    fi
    
    log_info "Enabling VPN gateway mode..."
    log_info "External interface: $EXT_IFACE"
    log_info "VPN subnet: $VPN_SUBNET"
    
    # Enable IP forwarding
    log_info "Enabling IP forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    
    # Make persistent (if sysctl.conf exists)
    if [ -f /etc/sysctl.conf ]; then
        if ! grep -q "net.ipv4.ip_forward" /etc/sysctl.conf; then
            echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        else
            sed -i 's/net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
        fi
    fi
    
    # Setup NAT
    log_info "Setting up NAT/masquerading..."
    
    # Remove existing rules first (ignore errors)
    iptables -t nat -D POSTROUTING -s $VPN_SUBNET -o $EXT_IFACE -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i $TUN_IFACE -o $EXT_IFACE -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i $EXT_IFACE -o $TUN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    
    # Add rules
    iptables -t nat -A POSTROUTING -s $VPN_SUBNET -o $EXT_IFACE -j MASQUERADE
    iptables -A FORWARD -i $TUN_IFACE -o $EXT_IFACE -j ACCEPT
    iptables -A FORWARD -i $EXT_IFACE -o $TUN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    log_info "Gateway mode enabled!"
    echo ""
    echo "Clients can now route their traffic through this VPN server."
    echo "Client config should have:"
    echo "  [routing]"
    echo "  route_all_traffic = true"
}

disable_gateway() {
    local EXT_IFACE=$1
    
    log_info "Disabling VPN gateway mode..."
    
    # Disable IP forwarding
    echo 0 > /proc/sys/net/ipv4/ip_forward
    
    # Remove NAT rules (ignore errors)
    if [ -n "$EXT_IFACE" ]; then
        iptables -t nat -D POSTROUTING -s $VPN_SUBNET -o $EXT_IFACE -j MASQUERADE 2>/dev/null || true
        iptables -D FORWARD -i $TUN_IFACE -o $EXT_IFACE -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -i $EXT_IFACE -o $TUN_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    fi
    
    log_info "Gateway mode disabled"
}

# Main
check_root

case "${1:-status}" in
    enable)
        enable_gateway "$2"
        ;;
    disable)
        disable_gateway "$2"
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {enable|disable|status} [interface]"
        echo ""
        echo "Commands:"
        echo "  enable <iface>   Enable gateway mode with specified external interface"
        echo "  disable [iface]  Disable gateway mode"
        echo "  status           Show current gateway status"
        echo ""
        echo "Examples:"
        echo "  $0 enable eth0    # Use eth0 as external interface"
        echo "  $0 enable enp0s3  # Use enp0s3 as external interface"
        echo "  $0 disable"
        exit 1
        ;;
esac
