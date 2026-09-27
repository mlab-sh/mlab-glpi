#!/usr/bin/env python3
"""Push fake glpi-agent inventories to GLPI native inventory. Usage: python3 seed/seed.py [http://localhost:8080]"""
import json, sys, urllib.request, uuid

GLPI = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080").rstrip("/")

WIN11 = {"name": "Windows", "full_name": "Microsoft Windows 11 Professionnel", "version": "23H2", "arch": "64-bit", "kernel_name": "MSWin32", "kernel_version": "10.0.22631"}
WIN10 = {"name": "Windows", "full_name": "Microsoft Windows 10 Entreprise", "version": "22H2", "arch": "64-bit", "kernel_name": "MSWin32", "kernel_version": "10.0.19045"}
DEB12 = {"name": "Debian", "full_name": "Debian GNU/Linux 12 (bookworm)", "version": "12", "arch": "x86_64", "kernel_name": "linux", "kernel_version": "6.1.0-13-amd64"}
UB2204 = {"name": "Ubuntu", "full_name": "Ubuntu 22.04.3 LTS", "version": "22.04.3 LTS (Jammy Jellyfish)", "arch": "x86_64", "kernel_name": "linux", "kernel_version": "5.15.0-88-generic"}
ROCKY9 = {"name": "Rocky Linux", "full_name": "Rocky Linux 9.2 (Blue Onyx)", "version": "9.2", "arch": "x86_64", "kernel_name": "linux", "kernel_version": "5.14.0-284.11.1.el9_2.x86_64"}
ALPINE = {"name": "Alpine Linux", "full_name": "Alpine Linux v3.18", "version": "3.18.4", "arch": "x86_64", "kernel_name": "linux", "kernel_version": "6.1.55-0-lts"}

MACHINES = {
    "WIN-COMPTA-01": (WIN11, [
        ("Google Chrome", "118.0.5993.70", "Google LLC"),
        ("7-Zip 23.01 (x64)", "23.01", "Igor Pavlov"),
        ("Notepad++ (64-bit x64)", "8.5.8", "Notepad++ Team"),
        ("VLC media player", "3.0.18", "VideoLAN"),
        ("WinRAR 6.22 (64-bit)", "6.22.0", "win.rar GmbH"),
        ("Mozilla Firefox (x64 fr)", "118.0.1", "Mozilla"),
        ("Adobe Acrobat Reader DC - Français", "23.003.20284", "Adobe Systems Incorporated"),
        ("Microsoft 365 Apps for enterprise - fr-fr", "16.0.16827.20166", "Microsoft Corporation"),
    ]),
    "WIN-RH-02": (WIN10, [
        ("Google Chrome", "128.0.6613.120", "Google LLC"),
        ("7-Zip 24.09 (x64)", "24.09", "Igor Pavlov"),
        ("KeePass Password Safe 2.53", "2.53.0", "Dominik Reichl"),
        ("AnyDesk", "7.1.0", "AnyDesk Software GmbH"),
        ("TeamViewer", "15.40.8", "TeamViewer"),
        ("PuTTY release 0.79 (64-bit)", "0.79.0.0", "Simon Tatham"),
    ]),
    "WIN-DEV-03": (WIN11, [
        ("Google Chrome", "118.0.5993.70", "Google LLC"),
        ("WinSCP 5.21.8", "5.21.8", "Martin Prikryl"),
        ("FileZilla 3.60.0", "3.60.0", "Tim Kosse"),
        ("Wireshark 4.0.6 x64", "4.0.6", "The Wireshark developer community"),
        ("OpenVPN 2.6.4-I001 amd64", "2.6.4", "OpenVPN, Inc."),
        ("LibreOffice 7.5.3.2", "7.5.3.2", "The Document Foundation"),
        ("Microsoft Edge", "116.0.1938.62", "Microsoft Corporation"),
        ("Git", "2.42.0.2", "The Git Development Community"),
    ]),
    "SRV-WEB-01": (DEB12, [
        ("openssl", "3.0.11-1~deb12u1", ""), ("sudo", "1.9.13p3-1", ""), ("curl", "7.88.1-10+deb12u4", ""),
        ("nginx", "1.22.1-9", ""), ("bash", "5.2.15-2+b2", ""), ("xz-utils", "5.4.1-0.2", ""), ("openssh-server", "1:9.2p1-2+deb12u1", ""),
    ]),
    "SRV-DB-02": (UB2204, [
        ("openssl", "3.0.2-0ubuntu1.10", ""), ("sudo", "1.9.9-1ubuntu2.4", ""), ("curl", "7.81.0-1ubuntu1.14", ""), ("vim", "2:8.2.3995-1ubuntu2.12", ""),
    ]),
    "SRV-APP-03": (ROCKY9, [
        ("openssl", "1:3.0.7-6.el9_2", ""), ("sudo", "1.9.5p2-9.el9", ""), ("curl", "7.76.1-23.el9_2.1", ""),
    ]),
    "SRV-EDGE-04": (ALPINE, [
        ("openssl", "3.1.0-r0", ""), ("busybox", "1.36.1-r2", ""), ("curl", "8.2.1-r0", ""),
    ]),
}

for name, (os_, softs) in MACHINES.items():
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, name + ".mlab.test"))
    inv = {
        "action": "inventory",
        "deviceid": f"{name}-2026-09-27-10-00-00",
        "itemtype": "Computer",
        "content": {
            "hardware": {"name": name, "uuid": uid},
            "bios": {"ssn": uid[:12].upper()},
            "operatingsystem": os_,
            "softwares": [{"name": n, "version": v, **({"publisher": p} if p else {})} for n, v, p in softs],
            "versionclient": "GLPI-Agent_v1.11",
        },
    }
    req = urllib.request.Request(f"{GLPI}/Inventory", json.dumps(inv).encode(), {"Content-Type": "application/json", "User-Agent": "GLPI-Agent_v1.11"})
    try:
        with urllib.request.urlopen(req) as r:
            print(name, r.status, r.read()[:120].decode(errors="replace"))
    except urllib.error.HTTPError as e:
        print(name, e.code, e.read()[:400].decode(errors="replace"))
