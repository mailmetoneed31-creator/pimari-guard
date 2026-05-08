#!/bin/bash
echo "[*] Termux প্যাকেজ আপডেট ও Python ইনস্টল..."
pkg update -y && pkg upgrade -y
pkg install python git -y

echo "[*] প্রয়োজনীয় Python লাইব্রেরি ইনস্টল..."
pip install --upgrade pip
pip install requests rich

# python-whois ইন্সটল করতে চাইলে:
# pkg install libffi openssl -y
# pip install python-whois

echo "[+] সব প্রস্তুত। এখন টুল রান করুন:"
echo "    python permi_guard.py --token-file token.txt"
