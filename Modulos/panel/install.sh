#!/bin/bash
# Instalador de V2Panel
set -e
[[ $EUID -ne 0 ]] && { echo "Ejecuta como root: sudo bash install.sh"; exit 1; }

DIR=/opt/v2panel
SRC="$(cd "$(dirname "$0")" && pwd)"
[[ -f "$SRC/v2panel.py" ]] || { echo "No encuentro v2panel.py junto a install.sh"; exit 1; }

command -v python3 >/dev/null || { apt-get update -y && apt-get install -y python3; }

mkdir -p "$DIR" /etc/v2panel
cp "$SRC/v2panel.py" "$DIR/v2panel.py"
chmod 700 "$DIR/v2panel.py"

python3 "$DIR/v2panel.py" setup

cat > /etc/systemd/system/v2panel.service <<UNIT
[Unit]
Description=V2Panel - panel web V2Ray
After=network.target

[Service]
ExecStart=/usr/bin/python3 $DIR/v2panel.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now v2panel
systemctl restart v2panel

PORT=$(python3 -c "import json;print(json.load(open('/etc/v2panel/config.json'))['port'])")
command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active" && ufw allow "$PORT"/tcp >/dev/null && echo "ufw: puerto $PORT abierto"
SCHEME=$(python3 -c "import json;print('https' if json.load(open('/etc/v2panel/config.json')).get('https') else 'http')")
IP=$(hostname -I | awk '{print $1}')

echo
echo "✔ V2Panel instalado"
echo "  Abre:  $SCHEME://$IP:$PORT   (con HTTPS usa el dominio del certificado)"
TOKEN=$(python3 "$DIR/v2panel.py" token)
echo
echo "  ── Para tu panel maestro (Agregar VPS) ──"
echo "  URL:    $SCHEME://$IP:$PORT/"
echo "  Token:  $TOKEN"
echo
echo "  Logs:  journalctl -u v2panel -f"
echo "  Cambiar contraseña/puerto: python3 $DIR/v2panel.py setup && systemctl restart v2panel"
