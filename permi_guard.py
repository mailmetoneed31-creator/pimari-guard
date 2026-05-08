#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Miraj Ahmad : OAuth Scope & Third-Party App Auditor
লেখক: Ethical Hacker Community
ব্যবহার: শুধুমাত্র নিজের বা অনুমোদিত অ্যাকাউন্টে!
"""

import os
import sys
import json
import argparse
import requests
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, List, Optional

# টারমিনাল সুন্দর করার জন্য Rich
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress
    from rich.panel import Panel
    from rich import print as rprint
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("[!] Rich লাইব্রেরি ইন্সটল না থাকলে ফলব্যাক মোডে চলবে। pip install rich")

console = Console() if RICH_AVAILABLE else None

# ------------------------------------------------------------
# ০. কনফিগ ও ইউটিলিটি
# ------------------------------------------------------------

BANNER = r"""
[bold cyan]
██████╗ ███████╗██████╗ ███╗   ███╗██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██╔══██╗██╔════╝██╔══██╗████╗ ████║██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██████╔╝█████╗  ██████╔╝██╔████╔██║██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔═══╝ ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║     ███████╗██║  ██║██║ ╚═╝ ██║██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
[/bold cyan]
[bold yellow]        OAuth Scope Auditor & App Risk Analyzer (v1.0 Advanced)[/bold yellow]
"""

def load_json_file(filepath: str) -> dict:
    """একটি JSON ফাইল লোড করে ডিকশনারি রিটার্ন করে।"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] {filepath} লোড করতে সমস্যা: {e}")
        sys.exit(1)

def validate_token(platform: str, token: str) -> Optional[str]:
    """টোকেন ভ্যালিড করে ইউজার আইডি রিটার্ন করে।"""
    if platform == "facebook":
        url = f"https://graph.facebook.com/v19.0/me?access_token={token}"
        try:
            resp = requests.get(url, timeout=15)
            data = resp.json()
            if 'id' in data:
                return data['id']
            else:
                error_msg = data.get('error', {}).get('message', 'Unknown error')
                print(f"[✘] টোকেন অবৈধ: {error_msg}")
                return None
        except Exception as e:
            print(f"[✘] সংযোগ ত্রুটি: {e}")
            return None
    else:
        print("[✘] বর্তমানে শুধুমাত্র Facebook প্ল্যাটফর্ম সাপোর্ট করছে।")
        return None

# ------------------------------------------------------------
# ১. ডাটা ফেচার: সংযুক্ত অ্যাপ ও পারমিশন
# ------------------------------------------------------------

def get_facebook_apps(token: str, user_id: str) -> List[Dict]:
    """Facebook Graph API থেকে সকল অ্যাপ ও তাদের পারমিশন নিয়ে আসে।"""
    url = f"https://graph.facebook.com/v19.0/{user_id}/permissions?access_token={token}"
    apps = []
    try:
        while url:
            resp = requests.get(url, timeout=15)
            data = resp.json()
            if 'data' in data:
                apps.extend(data['data'])
            # পেজিনেশন
            url = data.get('paging', {}).get('next')
        return apps
    except Exception as e:
        print(f"[!] অ্যাপ তালিকা আনতে ব্যর্থ: {e}")
        return []

def enrich_app_details(app: Dict) -> Dict:
    """প্রয়োজনীয় ফিল্ড সংযোজন, অ্যাপের অতিরিক্ত তথ্য (যেমন নাম) আপডেট করা।"""
    # ফেসবুক শুধু app_id ও granted_scopes দেয়, নাম দেয় না সাধারণত।
    # নাম পেতে /{app_id} এন্ডপয়েন্ট ব্যবহার করতে হবে।
    # নিচে একটি ফাংশন করে নিন
    app['app_name'] = app.get('app_name', 'Unknown')
    return app

def get_app_name(token: str, app_id: str) -> str:
    """অ্যাপের নাম Graph API থেকে আনে।"""
    try:
        url = f"https://graph.facebook.com/v19.0/{app_id}?access_token={token}"
        resp = requests.get(url, timeout=10)
        data = resp.json()
        return data.get('name', 'Unknown')
    except:
        return 'Unknown'

# ------------------------------------------------------------
# ২. রিস্ক এনালাইসিস ইঞ্জিন
# ------------------------------------------------------------

def load_scopes_map(filepath="scopes_map.json") -> dict:
    if not os.path.exists(filepath):
        # বিল্ট-ইন ফ্যালব্যাক
        print("[!] scopes_map.json পাওয়া যায়নি। বিল্ট-ইন ডেটা ব্যবহার করা হবে।")
        return {
            "publish_actions": 90,
            "manage_pages": 85,
            "read_insights": 70,
            "read_mailbox": 95,
            "user_friends": 50,
            "user_birthday": 40,
            "user_location": 60,
            "email": 45,
            "public_profile": 5,
            "groups_access_member_info": 70,
            "pages_show_list": 30,
            "ads_management": 80,
            "leads_retrieval": 75
        }
    return load_json_file(filepath)

def calculate_risk(permissions: List[str], scopes_scores: dict) -> dict:
    """সব স্কোরের মধ্যে সর্বোচ্চ রিটার্ন, প্লাস ক্রিটিক্যাল পারমিশন তালিকা।"""
    max_score = 0
    critical_scopes = []
    for perm in permissions:
        score = scopes_scores.get(perm, 20)  # অজানা পারমিশন মিডিয়াম
        if score > max_score:
            max_score = score
        if score >= 70:
            critical_scopes.append(perm)
    risk_level = "low"
    if max_score >= 70:
        risk_level = "high"
    elif max_score >= 40:
        risk_level = "medium"
    return {
        "max_score": max_score,
        "risk_level": risk_level,
        "critical_scopes": critical_scopes
    }

# ------------------------------------------------------------
# ৩. (অপশনাল) অ্যাডভান্সড রিকন
# ------------------------------------------------------------

def check_domain_https(domain: str) -> bool:
    """ডোমেইনের TLS সার্টিফিকেট চেক (সারফেস লেভেল)।"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except:
        return False

def deep_scan_app(app: Dict, token: str) -> Dict:
    """প্রতিটি অ্যাপের জন্য ডোমেইন রিকন ও অতিরিক্ত তথ্য যোগ করে।"""
    app_id = app.get('id')
    app['app_name'] = get_app_name(token, app_id)
    # ডোমেইন পেতে /{app_id}?fields=website ইত্যাদি
    try:
        url = f"https://graph.facebook.com/v19.0/{app_id}?fields=website,link&access_token={token}"
        r = requests.get(url, timeout=10)
        data = r.json()
        website = data.get('website', '')
        if not website:
            website = data.get('link', '')
        if website:
            domain = urlparse(website).netloc
            app['domain'] = domain
            app['https'] = check_domain_https(domain)
        else:
            app['domain'] = None
            app['https'] = None
    except:
        app['domain'] = None
        app['https'] = None
    return app

# ------------------------------------------------------------
# ৪. রিপোর্ট জেনারেশন
# ------------------------------------------------------------

def generate_report(apps_risk: List[Dict], output_file: str = None):
    """Rich টেবিল ও মার্কডাউন রিপোর্ট তৈরি করে।"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # টার্মিনাল টেবিল
    if RICH_AVAILABLE:
        table = Table(title=f"PermiGuard Report - {now}")
        table.add_column("App Name", style="cyan", no_wrap=True)
        table.add_column("Risk Level", justify="center")
        table.add_column("Score", justify="right")
        table.add_column("Critical Scopes", style="red")
        
        for app in apps_risk:
            risk = app['risk']
            level_color = {"high": "red", "medium": "yellow", "low": "green"}.get(risk['risk_level'], "white")
            table.add_row(
                app.get('app_name', 'Unknown'),
                f"[{level_color}]{risk['risk_level'].upper()}[/{level_color}]",
                str(risk['max_score']),
                ', '.join(risk['critical_scopes']) if risk['critical_scopes'] else "None"
            )
        console.print(table)
    else:
        print("\n=== PermiGuard Report ===")
        for app in apps_risk:
            print(f"{app.get('app_name','Unknown'):<30} {app['risk']['risk_level']:<8} Score:{app['risk']['max_score']} | Critical: {', '.join(app['risk']['critical_scopes'])}")
    
    # মার্কডাউন ফাইল
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"# PermiGuard Audit Report\n\n**Date:** {now}\n\n")
            f.write("| App Name | Risk | Score | Critical Scopes | Domain | HTTPS |\n")
            f.write("|----------|------|-------|-----------------|--------|-------|\n")
            for app in apps_risk:
                f.write(f"| {app.get('app_name','Unknown')} | {app['risk']['risk_level']} | {app['risk']['max_score']} | {', '.join(app['risk']['critical_scopes'])} | {app.get('domain','N/A')} | {app.get('https','N/A')} |\n")
        print(f"[+] মার্কডাউন রিপোর্ট সংরক্ষিত: {output_file}")

# ------------------------------------------------------------
# ৫. (অপশনাল) রিভোক ফিচার
# ------------------------------------------------------------

def revoke_permission(token: str, user_id: str, app_id: str, permission: str):
    """একটি অ্যাপের কোনো নির্দিষ্ট পারমিশন রিভোক করে। সতর্কতা সহ।"""
    print(f"[WARN] আপনি {permission} পারমিশনটি {app_id} থেকে রিমুভ করতে যাচ্ছেন।")
    ans = input("চালিয়ে যেতে 'yes' লিখুন: ")
    if ans.lower() != 'yes':
        print("বাতিল করা হয়েছে।")
        return False
    url = f"https://graph.facebook.com/v19.0/{user_id}/permissions/{permission}"
    params = {"access_token": token}
    resp = requests.delete(url, params=params)
    if resp.status_code == 200:
        print(f"[✓] {permission} সফলভাবে রিভোক হয়েছে।")
        return True
    else:
        print(f"[✘] রিভোক ব্যর্থ: {resp.json().get('error', {}).get('message', 'Unknown')}")
        return False

# ------------------------------------------------------------
# ৬. মেইন ফাংশন
# ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PermiGuard-Advanced: OAuth Scope Auditor")
    parser.add_argument("--platform", choices=["facebook"], default="facebook", help="টার্গেট প্ল্যাটফর্ম (বর্তমানে শুধু facebook)")
    parser.add_argument("--token", help="Facebook Access Token")
    parser.add_argument("--token-file", help="টোকেন সংবলিত ফাইল")
    parser.add_argument("--deep", action="store_true", help="অ্যাডভান্সড ডোমেইন ও TLS স্ক্যান চালু")
    parser.add_argument("--output", help="মার্কডাউন রিপোর্ট ফাইলের নাম", default="permi_report.md")
    parser.add_argument("--revoke", help="একটি অ্যাপ ও পারমিশন রিভোক করতে ফর্ম্যাট: app_id:permission (যেমন 1234:email)")
    args = parser.parse_args()
    
    # ব্যানার
    if RICH_AVAILABLE:
        console.print(BANNER)
    else:
        print("PermiGuard-Advanced : Ethical OAuth Auditor")
    
    # টোকেন সংগ্রহ
    token = None
    if args.token:
        token = args.token
    elif args.token_file:
        try:
            with open(args.token_file, 'r') as f:
                token = f.read().strip()
        except Exception as e:
            print(f"[!] টোকেন ফাইল পড়া যায়নি: {e}")
            sys.exit(1)
    else:
        print("[!] --token অথবা --token-file দিতে হবে।")
        sys.exit(1)
    
    print("[*] টোকেন ভ্যালিডেট করা হচ্ছে...")
    user_id = validate_token(args.platform, token)
    if not user_id:
        sys.exit(1)
    print(f"[✓] ইউজার আইডি: {user_id}")
    
    # অ্যাপ সংগ্রহ
    print("[*] সংযুক্ত অ্যাপ ও পারমিশন আনা হচ্ছে...")
    apps = get_facebook_apps(token, user_id)
    if not apps:
        print("[!] কোনো অ্যাপ পাওয়া যায়নি অথবা কোনো পারমিশন নেই।")
        sys.exit(0)
    print(f"[+] মোট {len(apps)} টি অ্যাপ পাওয়া গেছে।")
    
    # ডিপ স্ক্যান (অ্যাপের নাম, ডোমেইন)
    if args.deep:
        print("[*] ডিপ স্ক্যান চলছে...")
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning apps...", total=len(apps))
            enriched = []
            for app in apps:
                app_enriched = deep_scan_app(app, token)
                enriched.append(app_enriched)
                progress.advance(task)
            apps = enriched
    else:
        # শুধু নাম যোগ করি
        for app in apps:
            app['app_name'] = get_app_name(token, app.get('id'))
    
    # রিস্ক অ্যানালাইসিস
    scopes_map = load_scopes_map()
    apps_risk = []
    for app in apps:
        permissions = app.get('permissions', [])
        risk = calculate_risk(permissions, scopes_map)
        app['risk'] = risk
        apps_risk.append(app)
    
    # রিভোক ফিচার (আলাদা কমান্ড হিসেবে)
    if args.revoke:
        parts = args.revoke.split(':')
        if len(parts) == 2:
            app_id, perm = parts[0], parts[1]
            revoke_permission(token, user_id, app_id, perm)
        else:
            print("[!] রিভোক ফর্ম্যাট: --revoke app_id:permission")
        return
    
    # রিপোর্ট
    generate_report(apps_risk, args.output)

if __name__ == "__main__":
    main()
