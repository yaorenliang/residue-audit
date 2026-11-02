#!/bin/sh
# Synthetic artifact set: writes five files whose metadata is shaped like the
# thing under study, so that residue has something to measure inside a
# throwaway guest.
#
# It is not an implant. It does not mine, connect, persist, or execute anything:
# every "service" it writes points at a text file that is never started.
#
# Usage: synthetic_implant.sh [ROOT] [--no-align]

set -eu

root=/
align=1
for arg in "$@"; do
    case "$arg" in
        --no-align) align=0 ;;
        *) root=$arg ;;
    esac
done

case "$root" in
    /*) ;;
    *) echo "PLANT_ERROR=root-must-be-absolute:$root"; exit 2 ;;
esac

old=1609459200  # 2021-01-01T00:00:00Z

for dir in etc/systemd/system etc/cron.d usr/libexec usr/local/bin; do
    mkdir -p "$root/$dir"
    for n in a b; do
        printf 'unrelated\n' > "$root/$dir/zzz-neighbour-$n"
        touch -t 202101010000 "$root/$dir/zzz-neighbour-$n"
    done
done

cat > "$root/etc/systemd/system/zz-harvest.service" <<'UNIT'
[Unit]
Description=harvest
[Service]
Restart=always
KillSignal=SIGCONT
SendSIGKILL=no
ExecStart=/usr/libexec/kworker --id x
UNIT

cat > "$root/etc/systemd/system/zz-bridge.service" <<'UNIT'
[Service]
Restart=always
KillSignal=SIGCONT
ExecStart=/usr/local/bin/bridge-client-x
UNIT

printf '*/17 * * * * root /usr/libexec/kworker --self-update\n' > "$root/etc/cron.d/kworkers-updater"
printf '\177ELF synthetic worker\n' > "$root/usr/libexec/kworker"
printf '\177ELF synthetic client\n' > "$root/usr/local/bin/bridge-client-x"
chmod 0755 "$root/usr/libexec/kworker" "$root/usr/local/bin/bridge-client-x"

if [ "$align" = "1" ]; then
    for file in etc/systemd/system/zz-harvest.service \
                etc/systemd/system/zz-bridge.service \
                etc/cron.d/kworkers-updater \
                usr/libexec/kworker \
                usr/local/bin/bridge-client-x; do
        touch -t 202101010000 "$root/$file"
    done
fi

echo "PLANT_OK=1 root=$root align=$align"
