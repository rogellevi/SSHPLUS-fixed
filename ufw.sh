#!/bin/bash

# ============================================================
# Script de instalación y configuración de UFW para Oracle Cloud
# ============================================================

set -e  # Detener el script si hay algún error

# Colores para mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # Sin color

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Este script debe ejecutarse como root (usa sudo)${NC}"
    exit 1
fi

echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}  Configuración de UFW para Oracle Cloud${NC}"
echo -e "${BLUE}=================================================${NC}"

# ------------------------------------------------------------
# 1. Actualizar repositorios e instalar UFW
# ------------------------------------------------------------
echo -e "\n${YELLOW}[1/6] Actualizando repositorios e instalando UFW...${NC}"
apt update -y
apt install ufw -y

# ------------------------------------------------------------
# 2. Habilitar reenvío de paquetes (necesario en Oracle Cloud)
# ------------------------------------------------------------
echo -e "\n${YELLOW}[2/6] Configurando reenvío de paquetes...${NC}"
sed -i 's/^#*net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

# ------------------------------------------------------------
# 3. Resetear UFW para partir de una configuración limpia
# ------------------------------------------------------------
echo -e "\n${YELLOW}[3/6] Reseteando reglas previas de UFW...${NC}"
ufw --force reset

# ------------------------------------------------------------
# 4. Políticas por defecto
# ------------------------------------------------------------
echo -e "\n${YELLOW}[4/6] Estableciendo políticas por defecto...${NC}"
ufw default deny incoming
ufw default allow outgoing

# ------------------------------------------------------------
# 5. Añadir reglas de puertos
# ------------------------------------------------------------
echo -e "\n${YELLOW}[5/6] Añadiendo reglas de puertos...${NC}"

# SSH
ufw allow 22/tcp    comment 'SSH TCP'
ufw allow 22/udp    comment 'SSH UDP'

# Rango 7100-7500
ufw allow 7100:7500/tcp comment 'Rango 7100-7500 TCP'
ufw allow 7100:7500/udp comment 'Rango 7100-7500 UDP'

# Rango 441-445
ufw allow 441:445/tcp   comment 'Rango 441-445 TCP'

# Puertos HTTP/HTTP-alt
for port in 80 8080 8888 5454 5555 7000 81; do
    ufw allow ${port}/tcp comment "Puerto ${port} TCP"
    ufw allow ${port}/udp comment "Puerto ${port} UDP"
done

# ------------------------------------------------------------
# 6. Habilitar UFW
# ------------------------------------------------------------
echo -e "\n${YELLOW}[6/6] Habilitando UFW...${NC}"
ufw --force enable

# Mostrar estado
echo -e "\n${GREEN}=== Estado de UFW ===${NC}"
ufw status verbose

# ------------------------------------------------------------
# 7. Eliminar netfilter-persistent (evita conflictos en Oracle Cloud)
# ------------------------------------------------------------
echo -e "\n${YELLOW}[+] Eliminando netfilter-persistent...${NC}"
apt remove netfilter-persistent -y
apt autoremove -y

# ------------------------------------------------------------
# 8. Persistir reglas de iptables manualmente (por si acaso)
# ------------------------------------------------------------
echo -e "\n${YELLOW}[+] Guardando reglas de UFW...${NC}"
ufw reload

echo -e "\n${GREEN}=================================================${NC}"
echo -e "${GREEN}  ✅ Configuración completada exitosamente${NC}"
echo -e "${GREEN}=================================================${NC}"
echo -e "${YELLOW}⚠️  El sistema se reiniciará en 10 segundos...${NC}"
echo -e "${YELLOW}   Presiona Ctrl+C para cancelar el reinicio${NC}"

sleep 10
reboot