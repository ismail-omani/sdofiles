#!/usr/bin/env bash
# narp — замена arp-scan без sudo
# Использование: ./narp.sh [интерфейс] [сеть/префикс]
set -u

IFACE=${1:-$(ip route show default | awk '/^default/ {print $5; exit}')}
CIDR=${2:-$(ip -4 route show dev "$IFACE" scope link | awk '/proto kernel/ {print $1; exit}')}
PORTS=${PORTS:-"80 443"}

if [ -z "${IFACE:-}" ] || [ -z "${CIDR:-}" ]; then
    echo "Использование: $0 [интерфейс] [сеть/префикс]" >&2
    exit 1
fi

ip2int() { local IFS=.; read -r a b c d <<< "$1"; echo $(( (a << 24) | (b << 16) | (c << 8) | d )); }
int2ip() { local v=$1; echo "$(( (v >> 24) & 255 )).$(( (v >> 16) & 255 )).$(( (v >> 8) & 255 )).$(( v & 255 ))"; }

net=${CIDR%/*}
pfx=${CIDR#*/}
mask=$(( (0xFFFFFFFF << (32 - pfx)) & 0xFFFFFFFF ))
base=$(( $(ip2int "$net") & mask ))
total=$(( 1 << (32 - pfx) ))
first=$(( base + 1 ))
last=$(( base + total - 2 ))
[ "$pfx" -ge 31 ] && last=$(( base + total - 1 ))

printf 'Интерфейс: %s   сеть: %s   хостов: %d\n\n' "$IFACE" "$CIDR" "$(( last - first + 1 ))"

# будим ARP-кэш: сначала ICMP, затем TCP (любой ответ/отказ тоже создаёт ARP-запись)
probe() {
    local ip=$1 p
    ping -c1 -W1 -n "$ip" >/dev/null 2>&1 && return 0
    for p in $PORTS; do
        timeout 1 bash -c "exec 3<>/dev/tcp/$ip/$p" 2>/dev/null && return 0
    done
    return 1
}
export -f probe int2ip
export PORTS

seq "$first" "$last" | xargs -P 128 -I{} bash -c 'probe "$(int2ip {})"' >/dev/null 2>&1
sleep 1

printf '%-15s %-18s %-30s %s\n' "IP" "MAC" "ПРОИЗВОДИТЕЛЬ" "ИМЯ"
ip neigh show dev "$IFACE" |
awk -v oui=/usr/share/nmap/nmap-mac-prefixes '
    BEGIN { while ((getline l < oui) > 0) { split(l, a, " "); v[toupper(a[1])] = substr(l, length(a[1]) + 1) } }
    /lladdr/ {
        ip = $1
        for (i = 1; i <= NF; i++) if ($i == "lladdr") mac = $(i + 1)
        if (mac == "") next
        key = toupper(substr(mac, 1, 2) substr(mac, 4, 2) substr(mac, 7, 2))
        name = v[key]; sub(/^ +/, "", name)
        if (name == "") name = "неизвестно"
        split(ip, o, ".")
        printf "%03d.%03d.%03d.%03d\t%s\t%s\t%s\n", o[1], o[2], o[3], o[4], ip, mac, name
    }' |
sort -t$'\t' -k1,1 |
cut -f2- |
while IFS=$'\t' read -r ip mac vendor; do
    name=$(timeout 1 getent hosts "$ip" | awk '{print $2; exit}')
    [ -z "$name" ] && name="-"
    printf '%-15s %-18s %-30s %s\n' "$ip" "$mac" "$vendor" "$name"
done
