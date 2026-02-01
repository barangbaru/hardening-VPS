<div align="center">
   <img width=100% src=https://capsule-render.vercel.app/api?type=waving&height=100&color=gradient&reversal=true />
</div>

<h1 align="center">
 VPS Hardening Script  

</h3>

### <picture> <img src = "https://github.com/7oSkaaa/7oSkaaa/blob/main/Images/OS.gif?raw=true" width = 50px>  </picture> Operating Systems
 
<p align="center">
  &emsp;
    <a href="#"><img src="https://img.shields.io/badge/Linux-FCC624?style=plastic&logo=linux&logoColor=black"></a>
  &emsp;
    <a href="#"><img src="https://img.shields.io/badge/Ubuntu-E95420?style=plastic&logo=ubuntu&logoColor=white"></a>
  &emsp;
    <a href="#"><img src="https://img.shields.io/badge/Windows-0078D6?style=plastic&logo=windows&logoColor=white"></a>
  &emsp;
</p>
<p align="center">
  <em>
Automated hardening script, dirancang untuk kebutuhan production, security baseline, dan compliance-oriented environment (ISO 27001 / SOC 2 style).
</em> 
  <br>
  <img src="https://media.giphy.com/media/gH3LO09IOiZIqePwv9/giphy.gif" width="50" /> <b><i align="center">Untuk Linux based server cript ini dapat dijalankan **langsung dari GitHub** dan mencakup logging, audit, SSH hardening, firewall, serta usability dasar untuk admin.</i></b> <img src="https://media.giphy.com/media/qjqUcgIyRjsl2/giphy.gif" width="50" />



</p>


<details> 
   <summary><img src="https://img.shields.io/badge/Ubuntu-E95420?style=plastic&logo=ubuntu&logoColor=white"> Ubuntu 24.04</summary>
<div>
  <samp>

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
```text
/var/log_activity/
├── command-history.log
├── command-history.log.1.gz
├── sudo.log
├── sudo.log.1.gz

/var/log/audit/audit.log
```
<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif"><br><br>
## <img src="https://media2.giphy.com/media/QssGEmpkyEOhBCb7e1/giphy.gif?cid=ecf05e47a0n3gi1bfqntqmob8g9aid1oyj2wr3ds3mg700bl&rid=giphy.gif" width ="25"><b>  Cara Instalasi</b> 

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
  </samp>
</div>
</details>

<details> 
   <summary><img src="https://img.shields.io/badge/Linux-FCC624?style=plastic&logo=linux&logoColor=black"> RHEL 9.7</summary>
<div>
  <samp>

### 🔐 Security & SSH Hardening
- ✅ Ubah **SSH port** dari `22` → `62`
- ✅ **SSH idle auto logout** setelah **15 menit**
- ✅ **FIREWALLD rules otomatis**
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
```text
/var/log_activity/
├── command-history.log
├── command-history.log.1.gz
├── sudo.log
├── sudo.log.1.gz

/var/log/audit/audit.log
```
<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif"><br><br>
## <img src="https://media2.giphy.com/media/QssGEmpkyEOhBCb7e1/giphy.gif?cid=ecf05e47a0n3gi1bfqntqmob8g9aid1oyj2wr3ds3mg700bl&rid=giphy.gif" width ="25"><b>  Cara Instalasi</b> 

🔹 Eksekusi Langsung dari GitHub (Recommended)
```sh
curl -fsSL https://raw.githubusercontent.com/barangbaru/hardening-VPS/refs/heads/main/setup-rhel9-hss.sh | sudo bash
```
🔹 Alternatif: Download lalu Jalankan
```sh
sudo su / sudo -i

curl -fsSL -o setup-ubuntu24-hss.sh \
https://raw.githubusercontent.com/barangbaru/hardening-VPS/main/setup-rhel9-hss.sh

chmod +x setup-rhel9-hss.sh
sudo ./setup-rhel9-hss.sh
```
  </samp>
</div>
</details>
<details> 
   <summary><img src="https://img.shields.io/badge/Windows-0078D6?style=plastic&logo=windows&logoColor=white"> Windows server 2022</summary>
<div>
  <samp>

### 🔐 Security & SSH Hardening
- ✅ Ubah **SSH port** dari `22` → `62`
- ✅ **SSH idle auto logout** setelah **15 menit**
- ✅ **FIREWALLD rules otomatis**
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
```text
/var/log_activity/
├── command-history.log
├── command-history.log.1.gz
├── sudo.log
├── sudo.log.1.gz

/var/log/audit/audit.log
```
<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif"><br><br>
## <img src="https://media2.giphy.com/media/QssGEmpkyEOhBCb7e1/giphy.gif?cid=ecf05e47a0n3gi1bfqntqmob8g9aid1oyj2wr3ds3mg700bl&rid=giphy.gif" width ="25"><b>  Cara Instalasi</b> 

🔹 Eksekusi Langsung dari GitHub menggunakan powershell as administrator (Recommended) 
```sh
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr https://raw.githubusercontent.com/barangbaru/hardening-VPS/refs/heads/main/setup-windows.ps1 -UseBasicParsing | iex"
```
🔹 Alternatif: Download lalu Jalankan
```sh
sudo su / sudo -i

curl -fsSL -o setup-ubuntu24-hss.sh \
https://raw.githubusercontent.com/barangbaru/hardening-VPS/main/setup-rhel9-hss.sh

chmod +x setup-rhel9-hss.sh
sudo ./setup-rhel9-hss.sh
```
  </samp>
</div>
</details>
