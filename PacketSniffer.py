#!/usr/bin/env python3
import socket
import struct
import sys
from datetime import datetime

PROTOCOLOS = {1: "ICMP", 6: "TCP", 17: "UDP"}

def mac_str(raw):return ":".join(f"{b:02x}" for b in raw)

def parse_ethernet(data):
    dest, src, proto = struct.unpack("!6s6sH", data[:14])
    return mac_str(dest), mac_str(src), proto, data[14:]

def parse_ipv4(data):
    ver_ihl = data[0]
    ihl = (ver_ihl & 0x0F) * 4
    ttl, proto, src, dst = struct.unpack("!8xBB2x4s4s", data[:20])
    return ttl, proto, socket.inet_ntoa(src), socket.inet_ntoa(dst), data[ihl:]

def parse_tcp(data):
    sport, dport, seq, ack, offset_flags = struct.unpack("!HHLLH", data[:14])
    offset = (offset_flags >> 12) * 4
    flags = offset_flags & 0x3F
    nombres = ["FIN", "SYN", "RST", "PSH", "ACK", "URG"]
    activos = [n for i, n in enumerate(nombres) if flags & (1 << i)]
    return sport, dport, seq, ack, activos, data[offset:]

def parse_udp(data):
    sport, dport, size = struct.unpack("!HHH2x", data[:8])
    return sport, dport, size, data[8:]

def parse_icmp(data):
    tipo, codigo, checksum = struct.unpack("!BBH", data[:4])
    return tipo, codigo, checksum, data[4:]

def mostrar_payload(payload, limite=64):
    if not payload:return
    parte = payload[:limite]
    texto = "".join(chr(b) if 32 <= b < 127 else "." for b in parte)
    print(f"    Payload ({len(payload)} bytes): {texto}")

maximo = int(sys.argv[1]) if len(sys.argv) > 1 else 0
try:sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except PermissionError:print("[!] Se necesitan permisos root. Ejecuta 'tsu' primero.");sys.exit(1)
except AttributeError:print("[!] AF_PACKET no está disponible en este sistema.");sys.exit(1)
print("[*] Capturando paquetes... (Ctrl+C para detener)\n")
contador = 0
try:
    while True:
        data, _ = sock.recvfrom(65535)
        contador += 1
        hora = datetime.now().strftime("%H:%M:%S")
        dst_mac, src_mac, eth_proto, payload = parse_ethernet(data)
        print(f"[{contador}] {hora} | Eth {src_mac} -> {dst_mac} | tipo 0x{eth_proto:04x}")
        if eth_proto == 0x0800:  # IPv4
            ttl, proto, src, dst, payload = parse_ipv4(payload)
            nombre = PROTOCOLOS.get(proto, str(proto))
            print(f"    IPv4 {src} -> {dst} | {nombre} | TTL {ttl}")
            if proto == 6 and len(payload) >= 14:
                sp, dp, seq, ack, flags, datos = parse_tcp(payload)
                print(f"    TCP {sp} -> {dp} | flags: {','.join(flags) or '-'}")
                mostrar_payload(datos)
            elif proto == 17 and len(payload) >= 8:
                sp, dp, size, datos = parse_udp(payload)
                print(f"    UDP {sp} -> {dp} | largo {size}")
                mostrar_payload(datos)
            elif proto == 1 and len(payload) >= 4:
                tipo, codigo, _, datos = parse_icmp(payload)
                print(f"    ICMP tipo {tipo} código {codigo}")
        elif eth_proto == 0x0806:print("    ARP")
        elif eth_proto == 0x86DD:print("    IPv6")
        print()
        if maximo and contador >= maximo:break
except KeyboardInterrupt:pass
finally:sock.close();print(f"\n[*] Captura finalizada. Paquetes capturados: {contador}")
