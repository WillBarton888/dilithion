#!/usr/bin/env python3
"""
Dilithion HD Wallet Interface Demo (Simple ASCII version for Windows)
"""

import sys
import time

# ANSI color codes
try:
    import os
    os.system('')  # Enable ANSI colors on Windows 10+
except:
    pass

C_RESET = "\033[0m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_CYAN = "\033[36m"
C_BOLD = "\033[1m"

SAMPLE_MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful"

def print_success(msg):
    print(f"{C_GREEN}[+] {msg}{C_RESET}")

def print_error(msg):
    print(f"{C_RED}[!] {msg}{C_RESET}")

def print_warning(msg):
    print(f"{C_YELLOW}[*] {msg}{C_RESET}")

def print_header(title):
    print(f"\n{C_CYAN}{C_BOLD}{'='*60}{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}{title.center(60)}{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}{'='*60}{C_RESET}\n")

def prompt_yn(msg):
    response = input(f"{C_YELLOW}{msg} (y/n): {C_RESET}").strip().lower()
    return response in ['y', 'yes']

def validate_passphrase(passphrase):
    if not passphrase:
        return 0, "No passphrase"

    score = min(len(passphrase) * 5, 50)
    if any(c.isupper() for c in passphrase): score += 10
    if any(c.islower() for c in passphrase): score += 10
    if any(c.isdigit() for c in passphrase): score += 10
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in passphrase): score += 20

    if score >= 90: return score, "Very Strong"
    elif score >= 70: return score, "Strong"
    elif score >= 50: return score, "Medium"
    elif score >= 30: return score, "Weak"
    else: return score, "Very Weak"

def demo_create_wallet():
    """Interactive wallet creation demo"""
    print_header("CREATE HD WALLET")

    # Security warning
    print(f"{C_RED}{C_BOLD}CRITICAL SECURITY WARNING{C_RESET}\n")
    print(f"{C_YELLOW}Your recovery phrase is the ONLY way to restore your wallet!{C_RESET}\n")

    print(f"{C_BOLD}DO:{C_RESET}")
    print("  [+] Write it down on paper")
    print("  [+] Store in a safe")
    print("  [+] Make multiple copies")
    print("  [+] Test restoration BEFORE funding\n")

    print(f"{C_BOLD}DON'T:{C_RESET}")
    print("  [-] Store in plain text file")
    print("  [-] Email or cloud storage")
    print("  [-] Take a photo")
    print("  [-] Share with anyone\n")

    print(f"{C_RED}If you lose this phrase, funds are PERMANENTLY LOST!{C_RESET}\n")

    if not prompt_yn("Have you read and understood the warning?"):
        print_warning("Wallet creation cancelled")
        return

    # Passphrase option
    print(f"\n{C_BOLD}Optional Passphrase (BIP39){C_RESET}")
    print("Extra security, but forgetting it means permanent fund loss!\n")

    passphrase = ""
    if prompt_yn("Do you want to add a passphrase?"):
        passphrase = input("Enter passphrase (or press Enter for none): ")
        if passphrase:
            score, strength = validate_passphrase(passphrase)
            if score < 50:
                print_warning(f"Passphrase strength: {strength} ({score}/100)")
                if not prompt_yn("Weak passphrase. Continue anyway?"):
                    print_warning("Cancelled")
                    return
            else:
                print(f"{C_GREEN}Passphrase strength: {strength} ({score}/100){C_RESET}")

            confirm = input("Confirm passphrase: ")
            if passphrase != confirm:
                print_error("Passphrases don't match!")
                return

    print(f"\n{C_YELLOW}Generating wallet...{C_RESET}")
    time.sleep(1)

    print()
    print_success("HD Wallet created successfully!")
    print()

    # Display mnemonic
    print(f"{C_RED}{C_BOLD}{'='*60}{C_RESET}")
    print(f"{C_RED}{C_BOLD}YOUR RECOVERY PHRASE (Write this down NOW!){C_RESET}")
    print(f"{C_RED}{C_BOLD}{'='*60}{C_RESET}\n")
    print(f"{C_BOLD}{SAMPLE_MNEMONIC}{C_RESET}\n")
    print(f"{C_RED}{C_BOLD}{'='*60}{C_RESET}\n")

    # First address
    sample_addr = "dil1qxyz123abc456def789ghi012jkl345mno678pqr901stu234vwx567yzabc"
    print(f"First address: {C_GREEN}{sample_addr}{C_RESET}\n")

    # Verify user wrote it down
    print(f"{C_YELLOW}IMPORTANT: Verify you wrote down your recovery phrase!{C_RESET}")
    first_word = SAMPLE_MNEMONIC.split()[0]
    user_word = input("Type the FIRST word to confirm: ")

    if user_word != first_word:
        print_warning(f"Verification failed! Expected: {first_word}")
    else:
        print_success("Verification successful!")

    print()

    # Backup option
    if prompt_yn("Create encrypted backup file now?"):
        print(f"\n{C_CYAN}Creating backup...{C_RESET}")
        time.sleep(0.5)
        backup_path = "C:\\Users\\will\\.dilithion\\backups\\wallet_backup_initial_20251110_143022.txt"
        print_success(f"Backup created: {backup_path}")
        print_warning("Keep this file secure!")

    print()
    show_security_checklist()

def demo_restore_wallet():
    """Interactive wallet restoration demo"""
    print_header("RESTORE HD WALLET FROM MNEMONIC")

    print("Enter your 24-word recovery phrase:")
    print("(separate words with spaces)")
    print(f"{C_YELLOW}> {C_RESET}", end="")
    mnemonic = input()

    if not mnemonic:
        print_error("No mnemonic provided")
        return

    word_count = len(mnemonic.split())
    if word_count != 24 and word_count != 12:
        print_warning(f"Expected 24 words, got {word_count}")

    print()
    if prompt_yn("Did you use a passphrase when creating this wallet?"):
        passphrase = input("Enter passphrase: ")

    print(f"\n{C_YELLOW}Restoring wallet...{C_RESET}")
    time.sleep(1.5)

    print()
    print_success("Wallet restored successfully!")
    print()

    sample_addr = "dil1qxyz123abc456def789ghi012jkl345mno678pqr901stu234vwx567yzabc"
    print(f"First address: {C_GREEN}{sample_addr}{C_RESET}\n")
    print_warning("Verify this address matches your previous wallet!")

    print("\nWallet state after restoration:")
    print("  Account: 0")
    print("  Generated addresses: 1\n")

    print_warning("Wallet will automatically scan for used addresses")
    print_warning("Generate more with 'getnewaddress' if needed\n")

    if prompt_yn("Create backup file now?"):
        print(f"\n{C_CYAN}Creating backup...{C_RESET}")
        time.sleep(0.5)
        print_success("Backup created: wallet_backup_restored_20251110_143500.txt")

def demo_export_mnemonic():
    """Interactive mnemonic export demo"""
    print_header("EXPORT MNEMONIC")

    print_warning("This will display your recovery phrase on screen")
    print_warning("Ensure no one can see your screen!\n")

    if not prompt_yn("Are you in a secure, private location?"):
        print_warning("Export cancelled")
        return

    print()
    time.sleep(0.5)

    print(f"\n{C_RED}{C_BOLD}{'='*60}{C_RESET}")
    print(f"{C_RED}{C_BOLD}YOUR RECOVERY PHRASE{C_RESET}")
    print(f"{C_RED}{C_BOLD}{'='*60}{C_RESET}\n")
    print(f"{C_BOLD}{SAMPLE_MNEMONIC}{C_RESET}\n")
    print(f"{C_RED}{C_BOLD}{'='*60}{C_RESET}\n")

    print_warning("Keep this phrase secure!\n")

def show_wallet_status():
    """Display wallet status demo"""
    print_header("WALLET STATUS")

    print(f"Wallet Type: {C_GREEN}HD (Hierarchical Deterministic){C_RESET}\n")
    print("Account: 0")
    print("Receive Addresses Generated: 15")
    print("Change Addresses Generated: 3\n")
    print(f"Encryption: {C_GREEN}Encrypted (UNLOCKED){C_RESET}\n")
    print(f"Auto-Backup: {C_GREEN}Enabled{C_RESET}")
    print("  Directory: C:\\Users\\will\\.dilithion\\backups")
    print("  Interval: 60 minutes\n")
    print(f"{C_BOLD}Security Recommendations:{C_RESET}")
    print(f"  {C_GREEN}[+] Wallet is well-protected{C_RESET}\n")

def show_security_checklist():
    """Display security checklist"""
    print_header("SECURITY CHECKLIST")

    print("Before funding your wallet, ensure:\n")
    print("  [ ] Recovery phrase written down on paper")
    print("  [ ] Recovery phrase stored in secure location (safe)")
    print("  [ ] Multiple backup copies in different locations")
    print("  [ ] Tested wallet restoration with recovery phrase")
    print("  [ ] Wallet encrypted with strong passphrase")
    print("  [ ] Auto-backup enabled (recommended)")
    print("  [ ] Computer scanned for malware")
    print("  [ ] No one else has seen your recovery phrase\n")
    print(f"{C_GREEN}Once complete, your wallet is ready for use!{C_RESET}\n")

def main_menu():
    """Main demo menu"""
    while True:
        print_header("DILITHION HD WALLET INTERFACE DEMO")
        print("This is a demonstration of the wallet interface.")
        print(f"{C_YELLOW}(No actual wallet operations are performed){C_RESET}\n")
        print("Choose an option:\n")
        print("  1. Interactive Wallet Creation")
        print("  2. Interactive Wallet Restoration")
        print("  3. Interactive Mnemonic Export")
        print("  4. Display Wallet Status")
        print("  5. Display Security Checklist")
        print("  6. Exit\n")

        choice = input(f"{C_CYAN}Enter choice (1-6): {C_RESET}").strip()
        print()

        if choice == '1':
            demo_create_wallet()
            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        elif choice == '2':
            demo_restore_wallet()
            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        elif choice == '3':
            demo_export_mnemonic()
            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        elif choice == '4':
            show_wallet_status()
            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        elif choice == '5':
            show_security_checklist()
            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        elif choice == '6':
            print(f"{C_GREEN}Thank you for trying the demo!{C_RESET}\n")
            break
        else:
            print_error("Invalid choice")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{C_YELLOW}Demo interrupted{C_RESET}\n")
