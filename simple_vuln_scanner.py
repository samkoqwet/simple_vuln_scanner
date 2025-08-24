import socket


zranitelnosti = {
    "Apache/2.4.49": "❌ Táto verzia Apache má známu zraniteľnosť (CVE-2021-41773).",
    "OpenSSH_7.2p2": "❌ Táto verzia SSH má slabiny (CVE-2016-6210).",
    "vsftpd 2.3.4": "❌ Táto verzia FTP má backdoor (CVE-2011-2523)."
}

def grab_banner(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()
        return banner
    except:
        return None

def scan_ports(host):
    print(f"🔍 Skenujem hostiteľa: {host}")
    for port in range(20, 1025):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"\n✅ Port {port} je otvorený")
                banner = grab_banner(host, port)
                if banner:
                    print(f"📌 Banner: {banner}")
                    # Skontrolujeme databázu
                    for vuln in zranitelnosti:
                        if vuln in banner:
                            print(zranitelnosti[vuln])
                else:
                    print("ℹ️ Žiadny banner")
            sock.close()
        except:
            pass


if __name__ == "__main__":
    scan_ports("127.0.0.1")
