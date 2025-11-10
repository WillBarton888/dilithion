#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dilithion HD Wallet Interface Demo
This script demonstrates the user-friendly wallet interface without requiring compilation.
"""

import sys
import time
import random
import os

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    os.system('chcp 65001 >nul')
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

# ANSI color codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_BLUE = "\033[34m"
COLOR_MAGENTA = "\033[35m"
COLOR_CYAN = "\033[36m"
COLOR_BOLD = "\033[1m"

# Sample mnemonic words for demo
SAMPLE_MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful"

def clear_screen():
    """Clear the screen (works on both Windows and Unix)"""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')

def print_box_header(title):
    """Print a fancy box header"""
    print()
    print(f"{COLOR_CYAN}{COLOR_BOLD}╔══════════════════════════════════════════════════════════════╗{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}║{title.center(62)}║{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}╚══════════════════════════════════════════════════════════════╝{COLOR_RESET}")
    print()

def print_security_warning():
    """Display critical security warning"""
    print()
    print(f"{COLOR_RED}{COLOR_BOLD}╔══════════════════════════════════════════════════════════════╗{COLOR_RESET}")
    print(f"{COLOR_RED}{COLOR_BOLD}║              CRITICAL SECURITY WARNING                       ║{COLOR_RESET}")
    print(f"{COLOR_RED}{COLOR_BOLD}╚══════════════════════════════════════════════════════════════╝{COLOR_RESET}")
    print()
    print(f"{COLOR_YELLOW}Your recovery phrase (mnemonic) is the ONLY way to restore your wallet!{COLOR_RESET}")
    print()
    print(f"{COLOR_BOLD}DO:{COLOR_RESET}")
    print("  ✓ Write it down on paper (pen, not pencil)")
    print("  ✓ Store in a fireproof/waterproof safe")
    print("  ✓ Make multiple copies in different locations")
    print("  ✓ Test restoration BEFORE funding wallet")
    print()
    print(f"{COLOR_BOLD}DON'T:{COLOR_RESET}")
    print("  ✗ Store in plain text file on computer")
    print("  ✗ Email to yourself or store in cloud")
    print("  ✗ Take a photo (can be hacked)")
    print("  ✗ Share with anyone (even support staff)")
    print()
    print(f"{COLOR_RED}If you lose this phrase, your funds are PERMANENTLY LOST!{COLOR_RESET}")
    print()

def print_passphrase_best_practices():
    """Display passphrase best practices"""
    print()
    print(f"{COLOR_CYAN}{COLOR_BOLD}Passphrase Best Practices:{COLOR_RESET}")
    print("  • Use 20+ characters")
    print("  • Mix uppercase, lowercase, numbers, symbols")
    print("  • Make it memorable but not guessable")
    print("  • Don't use personal info (birthday, name)")
    print("  • Don't reuse from other accounts")
    print()
    print(f"{COLOR_YELLOW}WARNING: If you forget passphrase, funds are LOST!{COLOR_RESET}")
    print()

def print_success(message):
    """Print success message"""
    print(f"{COLOR_GREEN}✓ {message}{COLOR_RESET}")

def print_error(message):
    """Print error message"""
    print(f"{COLOR_RED}✗ {message}{COLOR_RESET}")

def print_warning(message):
    """Print warning message"""
    print(f"{COLOR_YELLOW}⚠ {message}{COLOR_RESET}")

def print_info(message):
    """Print info message"""
    print(f"{COLOR_CYAN}ℹ {message}{COLOR_RESET}")

def prompt_confirmation(message):
    """Prompt user for yes/no confirmation"""
    response = input(f"{COLOR_YELLOW}{message} (y/n): {COLOR_RESET}").strip().lower()
    return response in ['y', 'yes']

def validate_passphrase_strength(passphrase):
    """Simple passphrase strength validation"""
    if not passphrase:
        return 0, "No passphrase"

    score = 0
    score += min(len(passphrase) * 5, 50)  # Length (max 50 points)

    if any(c.isupper() for c in passphrase):
        score += 10
    if any(c.islower() for c in passphrase):
        score += 10
    if any(c.isdigit() for c in passphrase):
        score += 10
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in passphrase):
        score += 20

    if score >= 90:
        return score, "Very Strong"
    elif score >= 70:
        return score, "Strong"
    elif score >= 50:
        return score, "Medium"
    elif score >= 30:
        return score, "Weak"
    else:
        return score, "Very Weak"

def demo_create_wallet():
    """Demo: Interactive wallet creation"""
    clear_screen()
    print_box_header("CREATE HIERARCHICAL DETERMINISTIC (HD) WALLET")

    # Security warning
    print_security_warning()

    if not prompt_confirmation("Have you read and understood the security warning?"):
        print_warning("Wallet creation cancelled")
        return

    print()

    # Passphrase option
    print(f"{COLOR_BOLD}Optional Passphrase (BIP39){COLOR_RESET}")
    print("Adding a passphrase provides extra security but:")
    print("  • You MUST remember both mnemonic AND passphrase")
    print("  • Forgetting passphrase = permanent loss of funds")
    print()

    passphrase = ""
    if prompt_confirmation("Do you want to add a passphrase?"):
        print_passphrase_best_practices()

        passphrase = input("Enter passphrase (or press Enter for none): ")

        if passphrase:
            score, strength = validate_passphrase_strength(passphrase)
            if score < 50:
                print_warning(f"Passphrase strength: {strength} ({score}/100)")
                if not prompt_confirmation("Passphrase is weak. Continue anyway?"):
                    print_warning("Wallet creation cancelled")
                    return
            else:
                print(f"{COLOR_GREEN}Passphrase strength: {strength} ({score}/100){COLOR_RESET}")

            passphrase_confirm = input("Confirm passphrase: ")
            if passphrase != passphrase_confirm:
                print_error("Passphrases don't match")
                return

    print()
    print(f"{COLOR_YELLOW}Generating wallet...{COLOR_RESET}")
    time.sleep(1)

    print()
    print_success("HD Wallet created successfully!")
    print()

    # Display mnemonic
    print(f"{COLOR_RED}{COLOR_BOLD}════════════════════════════════════════════════════════════════{COLOR_RESET}")
    print(f"{COLOR_RED}{COLOR_BOLD}YOUR RECOVERY PHRASE (Write this down NOW!){COLOR_RESET}")
    print(f"{COLOR_RED}{COLOR_BOLD}════════════════════════════════════════════════════════════════{COLOR_RESET}")
    print()
    print(f"{COLOR_BOLD}{SAMPLE_MNEMONIC}{COLOR_RESET}")
    print()
    print(f"{COLOR_RED}{COLOR_BOLD}════════════════════════════════════════════════════════════════{COLOR_RESET}")
    print()

    # First address
    sample_address = "dil1qxyz123abc456def789ghi012jkl345mno678pqr901stu234vwx567yzabc"
    print(f"First address: {COLOR_GREEN}{sample_address}{COLOR_RESET}")
    print()

    # Verify mnemonic
    print(f"{COLOR_YELLOW}IMPORTANT: Verify you have written down your recovery phrase!{COLOR_RESET}")
    first_word = SAMPLE_MNEMONIC.split()[0]
    user_word = input("Type the FIRST word of your recovery phrase to confirm: ")

    if user_word != first_word:
        print_warning(f"Verification failed! Please double-check your backup. (Expected: {first_word})")
    else:
        print_success("Verification successful!")

    print()

    # Backup option
    if prompt_confirmation("Create encrypted backup file now?"):
        print()
        print(f"{COLOR_CYAN}Creating backup...{COLOR_RESET}")
        time.sleep(0.5)
        backup_path = "C:\\Users\\will\\.dilithion\\backups\\wallet_backup_initial_20251110_143022.txt"
        print_success(f"Backup created: {backup_path}")
        print_warning("Keep this file secure!")

    print()
    display_security_checklist()

def demo_restore_wallet():
    """Demo: Interactive wallet restoration"""
    clear_screen()
    print_box_header("RESTORE HD WALLET FROM MNEMONIC")

    print("Enter your 24-word recovery phrase:")
    print("(separate words with spaces)")
    print(f"{COLOR_YELLOW}> {COLOR_RESET}", end="")
    mnemonic = input()

    if not mnemonic:
        print_error("No mnemonic provided")
        return

    word_count = len(mnemonic.split())
    if word_count != 24 and word_count != 12:
        print_warning(f"Expected 24 words (or 12 for lower security), got {word_count}")

    print()

    if prompt_confirmation("Did you use a passphrase when creating this wallet?"):
        passphrase = input("Enter passphrase: ")

    print()
    print(f"{COLOR_YELLOW}Restoring wallet...{COLOR_RESET}")
    time.sleep(1.5)

    print_success("Wallet restored successfully!")
    print()

    sample_address = "dil1qxyz123abc456def789ghi012jkl345mno678pqr901stu234vwx567yzabc"
    print(f"First address: {COLOR_GREEN}{sample_address}{COLOR_RESET}")
    print()

    print_warning("Verify this address matches your previous wallet!")
    print()

    print("Wallet state after restoration:")
    print("  Account: 0")
    print("  Generated addresses: 1")
    print()

    print_warning("The wallet will automatically scan for used addresses")
    print_warning("Generate more addresses with 'getnewaddress' if needed")
    print()

    if prompt_confirmation("Create backup file now?"):
        print()
        print(f"{COLOR_CYAN}Creating backup...{COLOR_RESET}")
        time.sleep(0.5)
        backup_path = "C:\\Users\\will\\.dilithion\\backups\\wallet_backup_restored_20251110_143500.txt"
        print_success(f"Backup created: {backup_path}")

def demo_export_mnemonic():
    """Demo: Interactive mnemonic export"""
    clear_screen()
    print()
    print(f"{COLOR_RED}{COLOR_BOLD}╔══════════════════════════════════════════════════════════════╗{COLOR_RESET}")
    print(f"{COLOR_RED}{COLOR_BOLD}║                   EXPORT MNEMONIC                            ║{COLOR_RESET}")
    print(f"{COLOR_RED}{COLOR_BOLD}╚══════════════════════════════════════════════════════════════╝{COLOR_RESET}")
    print()

    print_warning("This will display your recovery phrase on screen")
    print_warning("Ensure no one can see your screen and no cameras are recording")
    print()

    if not prompt_confirmation("Are you in a secure, private location?"):
        print_warning("Export cancelled")
        return

    print()
    time.sleep(0.5)

    print()
    print(f"{COLOR_RED}{COLOR_BOLD}════════════════════════════════════════════════════════════════{COLOR_RESET}")
    print(f"{COLOR_RED}{COLOR_BOLD}YOUR RECOVERY PHRASE{COLOR_RESET}")
    print(f"{COLOR_RED}{COLOR_BOLD}════════════════════════════════════════════════════════════════{COLOR_RESET}")
    print()
    print(f"{COLOR_BOLD}{SAMPLE_MNEMONIC}{COLOR_RESET}")
    print()
    print(f"{COLOR_RED}{COLOR_BOLD}════════════════════════════════════════════════════════════════{COLOR_RESET}")
    print()

    print_warning("Keep this phrase secure!")
    print()

def display_wallet_status():
    """Demo: Display wallet status"""
    clear_screen()
    print()
    print(f"{COLOR_CYAN}{COLOR_BOLD}╔══════════════════════════════════════════════════════════════╗{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}║                  WALLET STATUS                               ║{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}╚══════════════════════════════════════════════════════════════╝{COLOR_RESET}")
    print()

    print(f"Wallet Type: {COLOR_GREEN}HD (Hierarchical Deterministic){COLOR_RESET}")
    print()

    print("Account: 0")
    print("Receive Addresses Generated: 15")
    print("Change Addresses Generated: 3")
    print()

    print(f"Encryption: {COLOR_GREEN}Encrypted (UNLOCKED){COLOR_RESET}")
    print()

    print(f"Auto-Backup: {COLOR_GREEN}Enabled{COLOR_RESET}")
    print("  Directory: C:\\Users\\will\\.dilithion\\backups")
    print("  Interval: 60 minutes")
    print()

    print(f"{COLOR_BOLD}Security Recommendations:{COLOR_RESET}")
    print(f"  {COLOR_GREEN}✓ Wallet is well-protected{COLOR_RESET}")
    print()

def display_security_checklist():
    """Display security checklist"""
    print()
    print(f"{COLOR_CYAN}{COLOR_BOLD}╔══════════════════════════════════════════════════════════════╗{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}║              SECURITY CHECKLIST                              ║{COLOR_RESET}")
    print(f"{COLOR_CYAN}{COLOR_BOLD}╚══════════════════════════════════════════════════════════════╝{COLOR_RESET}")
    print()

    print("Before funding your wallet, ensure:")
    print()
    print("  [ ] Recovery phrase written down on paper")
    print("  [ ] Recovery phrase stored in secure location (safe)")
    print("  [ ] Multiple backup copies in different locations")
    print("  [ ] Tested wallet restoration with recovery phrase")
    print("  [ ] Wallet encrypted with strong passphrase")
    print("  [ ] Auto-backup enabled (optional but recommended)")
    print("  [ ] Computer scanned for malware")
    print("  [ ] No one else has seen your recovery phrase")
    print()

    print(f"{COLOR_GREEN}Once checklist is complete, your wallet is ready for use!{COLOR_RESET}")
    print()

def main_menu():
    """Display main demo menu"""
    while True:
        clear_screen()
        print()
        print(f"{COLOR_CYAN}{COLOR_BOLD}╔══════════════════════════════════════════════════════════════╗{COLOR_RESET}")
        print(f"{COLOR_CYAN}{COLOR_BOLD}║        DILITHION HD WALLET INTERFACE DEMO                    ║{COLOR_RESET}")
        print(f"{COLOR_CYAN}{COLOR_BOLD}╚══════════════════════════════════════════════════════════════╝{COLOR_RESET}")
        print()
        print("This is a demonstration of the user-friendly wallet interface.")
        print(f"{COLOR_YELLOW}(No actual wallet operations are performed){COLOR_RESET}")
        print()
        print("Choose an option:")
        print()
        print("  1. Interactive Wallet Creation")
        print("  2. Interactive Wallet Restoration")
        print("  3. Interactive Mnemonic Export")
        print("  4. Display Wallet Status")
        print("  5. Display Security Checklist")
        print("  6. Exit")
        print()

        choice = input(f"{COLOR_CYAN}Enter choice (1-6): {COLOR_RESET}").strip()

        if choice == '1':
            demo_create_wallet()
            input(f"\n{COLOR_CYAN}Press Enter to continue...{COLOR_RESET}")
        elif choice == '2':
            demo_restore_wallet()
            input(f"\n{COLOR_CYAN}Press Enter to continue...{COLOR_RESET}")
        elif choice == '3':
            demo_export_mnemonic()
            input(f"\n{COLOR_CYAN}Press Enter to continue...{COLOR_RESET}")
        elif choice == '4':
            display_wallet_status()
            input(f"\n{COLOR_CYAN}Press Enter to continue...{COLOR_RESET}")
        elif choice == '5':
            clear_screen()
            display_security_checklist()
            input(f"\n{COLOR_CYAN}Press Enter to continue...{COLOR_RESET}")
        elif choice == '6':
            print()
            print(f"{COLOR_GREEN}Thank you for trying the Dilithion HD Wallet Interface Demo!{COLOR_RESET}")
            print()
            break
        else:
            print_error("Invalid choice")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print()
        print(f"\n{COLOR_YELLOW}Demo interrupted{COLOR_RESET}")
        print()
