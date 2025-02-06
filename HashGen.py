#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Created by Samip Mainali
# Hash Gen - Advanced Hash Generation Tool

import hashlib
import hmac
import sys
import os
import shutil
import re
from datetime import datetime
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)


class HashGen:
    """Main class for hash generation with enhanced features"""

    def __init__(self):
        # Terminal width detection with proper constraints
        self.terminal_width = max(min(shutil.get_terminal_size().columns, 100), 80)
        self.hash_algorithms = {
            "1": ("MD5", hashlib.md5),
            "2": ("SHA1", hashlib.sha1),
            "3": ("SHA256", hashlib.sha256),
            "4": ("SHA512", hashlib.sha512),
            "5": ("BLAKE2b", hashlib.blake2b),
            "6": ("SHA3-256", hashlib.sha3_256),
        }

        # Salt methods configuration
        self.salt_methods = {
            "1": ("Prepend", self._prepend_salt),
            "2": ("Append", self._append_salt),
            "3": ("Wrap", self._wrap_salt),
            "4": ("HMAC", self._hmac_salt),
            "5": ("Dual", self._dual_salt),
        }

        # Encoding options with improved detection
        self.encodings = {
            "1": ("Auto", self._smart_encode),
            "2": ("UTF-8", lambda x: x.encode("utf-8")),
            "3": ("Latin-1", lambda x: x.encode("latin-1")),
        }

    def _update_terminal_size(self):
        """Update terminal dimensions for responsive display"""
        self.terminal_width = max(min(shutil.get_terminal_size().columns - 2, 100), 80)

    def _print_header(self):
        """Display header without ASCII art banner"""
        self._update_terminal_size()
        print(
            Fore.MAGENTA
            + Style.BRIGHT
            + "           Hash Gen - Secure Hash Generator".center(self.terminal_width)
        )
        print(Fore.YELLOW + "═" * self.terminal_width + Style.RESET_ALL)

    def _smart_encode(self, text: str) -> bytes:
        """Smart encoding detection with special character handling"""
        try:
            if any(ord(char) > 127 for char in text):
                return text.encode("latin-1")
            return text.encode("utf-8")
        except UnicodeEncodeError:
            return text.encode("latin-1", errors="replace")

    # Region: Salt Application Methods
    def _prepend_salt(self, data: bytes, salt: bytes) -> bytes:
        """Prepend salt to the input data"""
        return salt + data

    def _append_salt(self, data: bytes, salt: bytes) -> bytes:
        """Append salt to the input data"""
        return data + salt

    def _wrap_salt(self, data: bytes, salt: bytes) -> bytes:
        """Wrap data with salt on both ends"""
        return salt + data + salt

    def _hmac_salt(self, data: bytes, salt: bytes) -> bytes:
        """HMAC-based salting using SHA-256"""
        return hmac.new(salt, data, digestmod=hashlib.sha256).digest()

    def _dual_salt(self, data: bytes, salt: bytes) -> bytes:
        """Dual salt application using || separator"""
        salt_parts = salt.split(b"||") if b"||" in salt else [salt, b""]
        return salt_parts[0] + data + salt_parts[1]

    # End Region

    def _sanitize_filename(self, text: str) -> str:
        """Sanitize strings for safe filenames"""
        sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", text)
        return sanitized[:25]  # Truncate to 25 chars

    def _get_choice(self, prompt: str, options: dict) -> str:
        """Display options and validate user input"""
        print(Fore.YELLOW + Style.BRIGHT + f"\n{prompt}")
        for key, (name, _) in options.items():
            print(f"  {Fore.CYAN}{Style.BRIGHT}[{key}] {name}")

        while True:
            choice = input(Fore.WHITE + Style.BRIGHT + "  Your choice ➜ ").strip()
            if choice in options:
                return choice
            print(Fore.RED + Style.BRIGHT + "  ✖ Invalid choice, please try again")

    def _validate_input(self, prompt: str) -> str:
        """Ensure required fields are not empty"""
        while True:
            value = input(Fore.WHITE + Style.BRIGHT + prompt).strip()
            if value:
                return value
            print(Fore.RED + Style.BRIGHT + "  ✖ This field cannot be empty!")

    def _save_to_file(self, result_data: dict):
        """Save results with improved dual salt handling"""
        # Sanitize components for filename
        algo = self._sanitize_filename(result_data["Algorithm"])
        method = self._sanitize_filename(result_data["Salt Method"])
        text = self._sanitize_filename(result_data["Text"])

        # Process salt for filename (split and sanitize parts)
        salt_parts = result_data["Salt"].split("||")
        sanitized_salt_parts = [self._sanitize_filename(part) for part in salt_parts]
        salt_for_filename = "_".join(sanitized_salt_parts)

        filename = f"{algo}_{method}_{text}_{salt_for_filename}.txt"

        try:
            with open(filename, "w") as f:
                # Write original values including || in salt
                f.write(f"text:{result_data['Text']}\n")
                f.write(f"salt:{result_data['Salt']}\n")
                f.write(f"hash:{result_data['Hash']}\n")
            print(Fore.GREEN + Style.BRIGHT + f"\n✓ Results saved to {filename}")
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + f"\n✖ Error saving file: {str(e)}")

    def _display_results(self, result_data: dict):
        """Display results in a clean, aligned format without boxes"""
        self._update_terminal_size()
        
        # Calculate column widths dynamically
        max_label_len = max(len(k) for k in result_data.keys())
        value_width = self.terminal_width - max_label_len - 4  # Account for ": " and margins
        
        # Create header
        header = " HASH GENERATION RESULTS ".center(self.terminal_width)
        print(Fore.CYAN + Style.BRIGHT + f"\n{header}")
        print(Fore.GREEN + "─" * self.terminal_width)
        
        # Display fields in consistent order
        fields = [
            ("Text", result_data["Text"]),
            ("Salt", result_data["Salt"]),
            ("Algorithm", result_data["Algorithm"]),
            ("Method", result_data["Salt Method"]),
            ("Encoding", result_data["Encoding"]),
            ("Double Hash", result_data["Double Hash"]),
            ("Hash", result_data["Hash"])
        ]
        
        for label, value in fields:
            # Truncate long values with ellipsis
            value_str = str(value)
            if len(value_str) > value_width:
                value_str = value_str[:value_width-3] + "..."

            # Format line with aligned columns
            line = f"{Fore.WHITE}{label:>{max_label_len}}: " + \
                   f"{Fore.CYAN}{value_str:<{value_width}}"
            print(line)

        print(Fore.GREEN + "─" * self.terminal_width)

    def generate_hash(
        self,
        text: str,
        salt: str,
        algorithm: str,
        salt_method: str,
        encoding: str,
        double_hash: bool,
        second_algorithm: str,
    ) -> dict:
        """Core hash generation logic with error handling"""
        result_data = {
            "Text": text,
            "Salt": salt,
            "Algorithm": self.hash_algorithms[algorithm][0],
            "Salt Method": self.salt_methods[salt_method][0],
            "Encoding": self.encodings[encoding][0],
            "Double Hash": "Yes" if double_hash else "No",
            "Hash": "Error",
        }

        try:
            # Encode inputs using selected method
            encoder = self.encodings[encoding][1]
            data_bytes = encoder(text)
            salt_bytes = encoder(salt)

            # Apply selected salt method
            salted_data = self.salt_methods[salt_method][1](data_bytes, salt_bytes)

            # First hashing stage
            hasher = self.hash_algorithms[algorithm][1]()
            hasher.update(salted_data)
            hash_result = hasher.hexdigest()

            # Optional double hashing
            if double_hash:
                second_hasher = self.hash_algorithms[second_algorithm][1]()
                hash_bytes = hash_result.encode("utf-8")
                salted_hash = self.salt_methods[salt_method][1](hash_bytes, salt_bytes)
                second_hasher.update(salted_hash)
                hash_result = second_hasher.hexdigest()

            result_data["Hash"] = hash_result
            return result_data

        except Exception as e:
            raise RuntimeError(f"Hashing error: {str(e)}")

    def interactive_mode(self):
        """Main interactive interface with session management"""
        while True:
            try:
                os.system("cls" if os.name == "nt" else "clear")
                self._print_header()

                # Collect user inputs
                text = self._validate_input("  Enter text to hash ➜ ")
                salt = input(Fore.WHITE + Style.BRIGHT + "  Enter salt (use '||' for dual salts) ➜ ").strip()

                # Skip salt method prompt if salt is empty
                salt_method = None
                if salt:
                    salt_method = self._get_choice("Select Salt Method:", self.salt_methods)

                # Configuration selections
                encoding = self._get_choice("Select Encoding Method:", self.encodings)
                algorithm = self._get_choice(
                    "Choose Hash Algorithm:", self.hash_algorithms
                )

                # Double hashing configuration
                double_hash = False
                second_algorithm = algorithm
                if (
                    input(
                        Fore.WHITE + Style.BRIGHT + "\nEnable double hashing? (y/n) ➜ "
                    ).lower()
                    == "y"
                ):
                    double_hash = True
                    second_algorithm = self._get_choice(
                        "Select Second Algorithm:", self.hash_algorithms
                    )

                # Generate and display results
                result_data = self.generate_hash(
                    text,
                    salt,
                    algorithm,
                    salt_method if salt else "1",  # default to no salt method if salt is empty
                    encoding,
                    double_hash,
                    second_algorithm,
                )
                self._display_results(result_data)

                # File save prompt
                if (
                    input(
                        Fore.WHITE + Style.BRIGHT + "\nSave results to file? (y/n) ➜ "
                    ).lower()
                    == "y"
                ):
                    self._save_to_file(result_data)

                # Continuation prompt
                if (
                    input(
                        Fore.WHITE + Style.BRIGHT + "\nGenerate another hash? (y/n) ➜ "
                    ).lower()
                    != "y"
                ):
                    print(
                        Fore.CYAN + Style.BRIGHT + "\nThank you for using Hash Gen! 🔒"
                    )
                    break

            except Exception as e:
                print(Fore.RED + Style.BRIGHT + f"\n⚠ Error: {str(e)}")
                if (
                    input(Fore.WHITE + Style.BRIGHT + "Continue? (y/n) ➜ ").lower()
                    != "y"
                ):
                    break


if __name__ == "__main__":
    try:
        HashGen().interactive_mode()
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"Fatal Error: {str(e)}")
        sys.exit(1)
