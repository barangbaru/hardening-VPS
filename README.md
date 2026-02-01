# hardening-VPS
Auto Hardening VPS server

# Ubuntu 24.04 VPS Hardening Script

Automated **hardening script untuk Ubuntu Server 24.04**, dirancang untuk kebutuhan **production**, **security baseline**, dan **compliance-oriented environment** (ISO 27001 / SOC 2 style).

Script ini dapat dijalankan **langsung dari GitHub** dan mencakup logging, audit, SSH hardening, firewall, serta usability dasar untuk admin.

---

## 🚀 Fitur Utama

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
