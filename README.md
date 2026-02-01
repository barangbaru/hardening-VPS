#  VPS Hardening Script

Automated **hardening script**, dirancang untuk kebutuhan **production**, **security baseline**, dan **compliance-oriented environment** (ISO 27001 / SOC 2 style).

Script ini dapat dijalankan **langsung dari GitHub** dan mencakup logging, audit, SSH hardening, firewall, serta usability dasar untuk admin.

---

## 🚀 Fitur Utama Ubuntu 24.04

### 🔐 Security & SSH Hardening
- ✅ Ubah **SSH port** dari `22` → `62`
- ✅ **SSH idle auto logout** setelah **15 menit**
- ✅ **UFW rules otomatis**
  - Allow `62/tcp`
  - Remove / deny `22`
- ✅ **Fail2ban aktif** untuk SSH port `62`
  - Max retry: 5
  - Ban time: 15 menit

---

### 🧾 Logging & Audit (Compliance Ready)
- ✅ **Auditd execve**
  - Mencatat seluruh command execution
- ✅ **Sudo logging**
  - Direlokasi ke `/var/log_activity/sudo.log`
- ✅ **User & Root history logging**
  - Timestamp lengkap (tanggal & jam)
  - Berlaku untuk:
    - Root login langsung
    - `sudo -i`
    - `sudo su -`
    - `su -`
- ✅ **Central command history log**

- ✅ **Retensi log 7 hari**
- Rotate harian
- Compress
- Menggunakan logrotate

---

### 🖥️ System & Usability
- ✅ **Docker Engine latest** (official Docker repository)
- ✅ **Docker Compose plugin**
- ✅ **Timezone Asia/Jakarta**
- ✅ **Dynamic MOTD + cache**
- Hostname
- Environment
- Public & Local IP
- Disk root usage
- CPU & Memory
- Users logged in
- ✅ **Disable banner & MOTD bawaan Ubuntu**
- ✅ **Netstat tersedia** (`net-tools`)

---

### 📁 Lokasi Log Penting

/var/log_activity/
├── command-history.log
├── command-history.log.1.gz
├── sudo.log
├── sudo.log.1.gz
/var/log/audit/audit.log

---

## 🚀 Cara Instalasi

🔹 Eksekusi Langsung dari GitHub (Recommended)
```sh
curl -fsSL https://raw.githubusercontent.com/barangbaru/hardening-VPS/refs/heads/main/setup-ubuntu24-hss.sh | sudo bash
```
🔹 Alternatif: Download lalu Jalankan
```sh
sudo su / sudo -i

curl -fsSL -o setup-ubuntu24-hss.sh \
https://raw.githubusercontent.com/barangbaru/hardening-VPS/main/setup-ubuntu24-hss.sh

chmod +x setup-ubuntu24-hss.sh
sudo ./setup-ubuntu24-hss.sh
```

