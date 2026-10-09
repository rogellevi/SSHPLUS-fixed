# 🚀 SSHPLUS MANAGER - Panel Web & Instalador Completo

![GitHub](https://img.shields.io/github/license/rogellevi/SSHPLUS-fixed)
![GitHub last commit](https://img.shields.io/github/last-commit/rogellevi/SSHPLUS-fixed)
![Debian/Ubuntu](https://img.shields.io/badge/OS-Debian%2FUbuntu-blue)

**SSHPLUS MANAGER** es un script bash interactivo diseñado para automatizar la instalación y configuración de **SSHPLUS**, un **Panel Web (Apache + PHP)** y la gestión de **Certificados SSL (Let's Encrypt / ACME.sh)** en servidores VPS.

---

## ✨ Características

- 🛠️ **Instalación Automatizada:** Despliega SSHPLUS, Apache2, PHP y dependencias.
- 🌐 **Panel Web:** Interfaz web para gestión de usuarios y conexiones.
- 🔒 **Soporte SSL:** Integración con Let's Encrypt o certificados existentes de `acme.sh`.
- 🛡️ **Seguridad:** Configuración automática de permisos, `sudoers` y puertos.
- 🔄 **Menú Interactivo:** Fácil navegación para instalar, actualizar o renovar componentes.
- ⚡ **Optimizado:** Desactiva el puerto 443 en Apache para evitar conflictos con V2Ray/Stunnel.

---

## 📋 Requisitos Previos

- Sistema Operativo: **Debian** o **Ubuntu** (Recomendado Ubuntu 20.04 / 22.04).
- Acceso **Root** (sudo).
- Un dominio apuntando a la IP de tu servidor (Solo para la opción SSL).

---

## ⚡ Instalación Rápida

Ejecuta el siguiente comando como usuario `root` para iniciar el instalador.


### INSTALL SCRIPT SSHPLUS

<pre><code>apt update -y && apt upgrade -y && wget https://raw.githubusercontent.com/rogellevi/SSHPLUS-fixed/master/Plus && chmod 777 Plus && ./Plus</code></pre>

### Instalación con Menú
```
wget -O manager.sh https://raw.githubusercontent.com/rogellevi/SSHPLUS-fixed/main/manager.sh && bash manager.sh
```

#### ROOT Y ABRIR PUERTOS
Primero Teclee : sudo su

Habilitar ROOT
~~~~
wget https://raw.githubusercontent.com/rogellevi/SSHPLUS-fixed/master/root && bash root
~~~~

Abrir Puertos:

~~~~
wget -O firewall https://raw.githubusercontent.com/rogellevi/SSHPLUS-fixed/main/firewall && chmod +x firewall && sudo ./firewall
~~~~
