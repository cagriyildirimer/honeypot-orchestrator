#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/start-lan.sh [--ip LAN_IP] [--parent IFACE] [--subnet CIDR] [--gateway IP] [--network NAME] [--detached] [--recreate-network]

Examples:
  scripts/start-lan.sh --ip 192.168.1.240
  scripts/start-lan.sh --ip 192.168.1.240 --parent eth0 --subnet 192.168.1.0/24 --gateway 192.168.1.1
  scripts/start-lan.sh --ip 192.168.1.240 --recreate-network
  scripts/start-lan.sh --detached

If --ip is omitted, the script proposes a high address in the detected /24 subnet.
Reserve the selected IP in your router/DHCP server when possible.
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

script_dir() {
  local source="${BASH_SOURCE[0]}"
  while [[ -h "$source" ]]; do
    local dir
    dir="$(cd -P "$(dirname "$source")" >/dev/null 2>&1 && pwd)"
    source="$(readlink "$source")"
    [[ "$source" != /* ]] && source="$dir/$source"
  done
  cd -P "$(dirname "$source")" >/dev/null 2>&1 && pwd
}

cidr_to_netmask() {
  local bits="$1"
  local mask=""
  local full_octets=$((bits / 8))
  local partial_bits=$((bits % 8))

  for index in 0 1 2 3; do
    if (( index < full_octets )); then
      mask+="255"
    elif (( index == full_octets )); then
      mask+="$((256 - (1 << (8 - partial_bits))))"
    else
      mask+="0"
    fi
    if (( index < 3 )); then
      mask+="."
    fi
  done
  echo "$mask"
}

network_from_ip_prefix() {
  local ip="$1"
  local prefix="$2"
  local IFS=.
  read -r i1 i2 i3 i4 <<< "$ip"
  read -r m1 m2 m3 m4 <<< "$(cidr_to_netmask "$prefix")"
  echo "$((i1 & m1)).$((i2 & m2)).$((i3 & m3)).$((i4 & m4))/$prefix"
}

suggest_ip() {
  local cidr="$1"
  local gateway="$2"
  local network="${cidr%/*}"
  local prefix="${cidr#*/}"
  local IFS=.
  read -r n1 n2 n3 n4 <<< "$network"

  if [[ "$prefix" != "24" ]]; then
    echo ""
    return
  fi

  for host in 240 241 242 243 244 245 246 247 248 249 250; do
    local candidate="$n1.$n2.$n3.$host"
    if [[ "$candidate" == "$gateway" ]]; then
      continue
    fi
    if ping -c 1 -W 1 "$candidate" >/dev/null 2>&1; then
      continue
    fi
    echo "$candidate"
    return
  done
}

confirm() {
  local prompt="$1"
  local answer=""
  read -r -p "$prompt [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" || "$answer" == "yes" || "$answer" == "YES" ]]
}

LAN_IP="${HONEYPOT_LAN_IP:-}"
LAN_PARENT="${HONEYPOT_LAN_PARENT:-}"
LAN_SUBNET="${HONEYPOT_LAN_SUBNET:-}"
LAN_GATEWAY="${HONEYPOT_LAN_GATEWAY:-}"
LAN_NETWORK="${HONEYPOT_LAN_NETWORK:-honeypot_lan_net}"
DETACHED=0
RECREATE_NETWORK=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ip)
      LAN_IP="${2:-}"
      shift 2
      ;;
    --parent)
      LAN_PARENT="${2:-}"
      shift 2
      ;;
    --subnet)
      LAN_SUBNET="${2:-}"
      shift 2
      ;;
    --gateway)
      LAN_GATEWAY="${2:-}"
      shift 2
      ;;
    --network)
      LAN_NETWORK="${2:-}"
      shift 2
      ;;
    --detached|-d)
      DETACHED=1
      shift
      ;;
    --recreate-network)
      RECREATE_NETWORK=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

require_command docker
require_command ip
require_command awk
require_command ping

REPO_ROOT="$(cd "$(script_dir)/.." >/dev/null 2>&1 && pwd)"
cd "$REPO_ROOT"

DEFAULT_ROUTE="$(ip route show default | head -n 1 || true)"
if [[ -z "$DEFAULT_ROUTE" ]]; then
  echo "Could not detect the default route. Pass --parent, --subnet, and --gateway explicitly." >&2
  exit 1
fi

if [[ -z "$LAN_PARENT" ]]; then
  LAN_PARENT="$(awk '{for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' <<< "$DEFAULT_ROUTE" | head -n 1)"
fi

if [[ -z "$LAN_GATEWAY" ]]; then
  LAN_GATEWAY="$(awk '{print $3}' <<< "$DEFAULT_ROUTE")"
fi

if [[ -z "$LAN_SUBNET" ]]; then
  IFACE_ADDR="$(ip -o -4 addr show dev "$LAN_PARENT" scope global | awk '{print $4}' | head -n 1)"
  if [[ -z "$IFACE_ADDR" ]]; then
    echo "Could not detect an IPv4 address on $LAN_PARENT. Pass --subnet explicitly." >&2
    exit 1
  fi
  IFACE_IP="${IFACE_ADDR%/*}"
  IFACE_PREFIX="${IFACE_ADDR#*/}"
  LAN_SUBNET="$(network_from_ip_prefix "$IFACE_IP" "$IFACE_PREFIX")"
fi

if [[ -z "$LAN_IP" ]]; then
  LAN_IP="$(suggest_ip "$LAN_SUBNET" "$LAN_GATEWAY")"
  if [[ -z "$LAN_IP" ]]; then
    echo "Could not safely suggest an IP for $LAN_SUBNET. Re-run with --ip LAN_IP." >&2
    exit 1
  fi
  echo "Suggested container IP: $LAN_IP"
  if ! confirm "Use this IP for the honeypot container?"; then
    echo "Aborted. Re-run with --ip LAN_IP when ready."
    exit 1
  fi
fi

if ping -c 1 -W 1 "$LAN_IP" >/dev/null 2>&1; then
  echo "Warning: $LAN_IP responded to ping. It may already be in use." >&2
  if ! confirm "Continue anyway?"; then
    exit 1
  fi
fi

export HONEYPOT_LAN_PARENT="$LAN_PARENT"
export HONEYPOT_LAN_SUBNET="$LAN_SUBNET"
export HONEYPOT_LAN_GATEWAY="$LAN_GATEWAY"
export HONEYPOT_LAN_IP="$LAN_IP"
export HONEYPOT_LAN_NETWORK="$LAN_NETWORK"

# Update or create the .env file with the selected LAN IP
if [[ -f .env ]]; then
  grep -v "^HONEYPOT_LAN_IP=" .env > .env.tmp || true
  echo "HONEYPOT_LAN_IP=$LAN_IP" >> .env.tmp
  mv .env.tmp .env
else
  echo "HONEYPOT_LAN_IP=$LAN_IP" > .env
fi

echo "Stopping host-published compose stack, if it is running"
docker compose -f docker-compose.yml down --remove-orphans >/dev/null 2>&1 || true

if (( RECREATE_NETWORK )); then
  if docker network inspect "$HONEYPOT_LAN_NETWORK" >/dev/null 2>&1; then
    echo "Recreating macvlan network: $HONEYPOT_LAN_NETWORK"
    docker compose -f docker-compose.lan.yml down --remove-orphans >/dev/null 2>&1 || true
    docker network rm "$HONEYPOT_LAN_NETWORK" >/dev/null
  fi
fi

if ! docker network inspect "$HONEYPOT_LAN_NETWORK" >/dev/null 2>&1; then
  echo "Creating macvlan network: $HONEYPOT_LAN_NETWORK"
  docker network create \
    -d macvlan \
    --subnet="$HONEYPOT_LAN_SUBNET" \
    --gateway="$HONEYPOT_LAN_GATEWAY" \
    -o parent="$HONEYPOT_LAN_PARENT" \
    "$HONEYPOT_LAN_NETWORK" >/dev/null
else
  echo "Using existing Docker network: $HONEYPOT_LAN_NETWORK"
fi

echo "Starting Honeypot Orchestrator LAN mode"
echo "  Interface : $HONEYPOT_LAN_PARENT"
echo "  Subnet    : $HONEYPOT_LAN_SUBNET"
echo "  Gateway   : $HONEYPOT_LAN_GATEWAY"
echo "  Network   : $HONEYPOT_LAN_NETWORK"
echo "  IP        : $HONEYPOT_LAN_IP"
echo "  Dashboard : http://$HONEYPOT_LAN_IP:8000"

if (( DETACHED )); then
  docker compose -f docker-compose.lan.yml up --build -d
  echo "Container network details:"
  docker inspect honeypot-orchestrator-lan \
    --format '  IP={{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}} Gateway={{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}'
  echo "Published host ports:"
  docker inspect honeypot-orchestrator-lan \
    --format '  {{json .NetworkSettings.Ports}}'
else
  docker compose -f docker-compose.lan.yml up --build
fi
