import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from PIL import Image, ImageTk, ImageDraw, ImageFont
import qrcode
import cv2
import numpy as np
import hashlib
import secrets
import base64
import os
import io
import pandas as pd
import zipfile
import uuid
import shutil
import re
import requests
import urllib.parse
from datetime import datetime

# Try to import cryptography, set flag if not available
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

class QRCodeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure QR Code Generator for MAT")
        self.root.geometry("650x900")
        self.root.configure(bg="#E6F0FA")
        
        # Variables
        self.qr_hash = None
        self.qr_filename = None
        self.destroyed_filename = "destroyed_qr.png"
        self.bulk_qr_data = []
        self.current_bulk_index = 0
        self.scan_history = []
        
        # Simulated blocklist (replace with Google Safe Browsing API in production)
        self.phishing_blocklist = [
            "malicious.example.com",
            "phishingsite.com",
            "rnicrosoftonline.com"  # Typosquatting example
        ]
        
        # Generate RSA key pair for digital signatures
        if CRYPTOGRAPHY_AVAILABLE:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
        else:
            self.private_key = None
            self.public_key = None
        
        # Styling
        self.style = {
            "bg": "#E6F0FA",
            "fg": "#333333",
            "frame_bg": "#F5F7FC",
            "button_bg": "#00C4B4",
            "button_fg": "white",
            "button_active": "#00A69B",
            "copy_button_bg": "#FFCA28",
            "copy_button_fg": "#212121",
            "copy_button_active": "#FFB300",
            "destroy_button_bg": "#FF5252",
            "destroy_button_active": "#D32F2F",
            "read_button_bg": "#3F51B5",
            "read_button_active": "#303F9F",
            "change_button_bg": "#FF7043",
            "change_button_active": "#F4511E",
            "export_button_bg": "#AB47BC",
            "export_button_active": "#8E24AA",
            "nav_button_bg": "#0288D1",
            "nav_button_active": "#01579B",
            "online_button_bg": "#7CB342",
            "online_button_active": "#558B2F",
            "verify_button_bg": "#FF4081",
            "verify_button_active": "#C51162",
            "report_button_bg": "#FF5722",
            "report_button_active": "#D84315",
            "preview_button_bg": "#4CAF50",
            "preview_button_active": "#388E3C",
            "history_button_bg": "#FBC02D",
            "history_button_active": "#F57F17",
            "font": ("Helvetica", 12),
            "title_font": ("Helvetica", 14, "bold"),
            "label_font": ("Helvetica", 11)
        }
        
        # Main Frame
        main_frame = tk.Frame(root, bg=self.style["frame_bg"], padx=20, pady=20, relief="groove", bd=2)
        main_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Title
        tk.Label(
            main_frame,
            text="Secure QR Code Generator for MAT",
            font=("Helvetica", 16, "bold"),
            bg=self.style["frame_bg"],
            fg="#0066CC"
        ).pack(pady=(0, 20))
        
        # Single QR Code Section
        single_frame = tk.LabelFrame(
            main_frame,
            text="Single QR Code",
            font=self.style["title_font"],
            bg=self.style["frame_bg"],
            fg=self.style["fg"],
            padx=10,
            pady=10
        )
        single_frame.pack(fill="x", pady=10)
        
        tk.Label(
            single_frame,
            text="Enter Data for QR Code:",
            font=self.style["label_font"],
            bg=self.style["frame_bg"]
        ).pack(anchor="w", pady=5)
        
        self.data_entry = tk.Entry(
            single_frame,
            width=40,
            font=self.style["font"],
            relief="flat",
            bg="#E6F0FA",
            highlightthickness=1,
            highlightbackground="#B0BEC5"
        )
        self.data_entry.pack(pady=5, padx=10, ipady=5)
        
        tk.Label(
            single_frame,
            text="Annotation (optional):",
            font=self.style["label_font"],
            bg=self.style["frame_bg"]
        ).pack(anchor="w", pady=5)
        
        self.annotation_entry = tk.Entry(
            single_frame,
            width=40,
            font=self.style["font"],
            relief="flat",
            bg="#E6F0FA",
            highlightthickness=1,
            highlightbackground="#B0BEC5"
        )
        self.annotation_entry.pack(pady=5, padx=10, ipady=5)
        
        # QR Code Customization
        config_frame = tk.Frame(single_frame, bg=self.style["frame_bg"])
        config_frame.pack(fill="x", pady=5)
        
        tk.Label(
            config_frame,
            text="QR Version (1-40):",
            font=self.style["label_font"],
            bg=self.style["frame_bg"]
        ).pack(side="left", padx=5)
        
        self.version_var = tk.StringVar(value="1")
        tk.Entry(
            config_frame,
            textvariable=self.version_var,
            width=5,
            font=self.style["font"],
            bg="#E6F0FA"
        ).pack(side="left", padx=5)
        
        tk.Label(
            config_frame,
            text="Error Correction:",
            font=self.style["label_font"],
            bg=self.style["frame_bg"]
        ).pack(side="left", padx=5)
        
        self.error_var = tk.StringVar(value="H")
        ttk.Combobox(
            config_frame,
            textvariable=self.error_var,
            values=["L", "M", "Q", "H"],
            width=5,
            state="readonly",
            font=self.style["font"]
        ).pack(side="left", padx=5)
        
        self.encrypt_var = tk.BooleanVar()
        self.encrypt_check = tk.Checkbutton(
            config_frame,
            text="Encrypt Data",
            variable=self.encrypt_var,
            font=self.style["label_font"],
            bg=self.style["frame_bg"],
            state="normal" if CRYPTOGRAPHY_AVAILABLE else "disabled",
            command=self.check_encryption
        )
        self.encrypt_check.pack(side="left", padx=5)
        
        # Color Customization
        color_frame = tk.Frame(single_frame, bg=self.style["frame_bg"])
        color_frame.pack(fill="x", pady=5)
        
        tk.Label(
            color_frame,
            text="Fill Color:",
            font=self.style["label_font"],
            bg=self.style["frame_bg"]
        ).pack(side="left", padx=5)
        
        self.fill_color_var = tk.StringVar(value="black")
        ttk.Combobox(
            color_frame,
            textvariable=self.fill_color_var,
            values=["black", "blue", "red", "green", "purple"],
            width=10,
            state="readonly",
            font=self.style["font"]
        ).pack(side="left", padx=5)
        
        tk.Label(
            color_frame,
            text="Background Color:",
            font=self.style["label_font"],
            bg=self.style["frame_bg"]
        ).pack(side="left", padx=5)
        
        self.back_color_var = tk.StringVar(value="white")
        ttk.Combobox(
            color_frame,
            textvariable=self.back_color_var,
            values=["white", "lightgrey", "yellow", "lightblue", "lightgreen"],
            width=10,
            state="readonly",
            font=self.style["font"]
        ).pack(side="left", padx=5)
        
        # Size Customization
        size_frame = tk.Frame(single_frame, bg=self.style["frame_bg"])
        size_frame.pack(fill="x", pady=5)
        
        tk.Label(
            size_frame,
            text="QR Size:",
            font=self.style["label_font"],
            bg=self.style["frame_bg"]
        ).pack(side="left", padx=5)
        
        self.size_var = tk.StringVar(value="Medium")
        ttk.Combobox(
            size_frame,
            textvariable=self.size_var,
            values=["Small", "Medium", "Large"],
            width=10,
            state="readonly",
            font=self.style["font"]
        ).pack(side="left", padx=5)
        
        tk.Button(
            single_frame,
            text="Generate QR Code",
            command=self.generate_qr,
            bg=self.style["button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["button_active"],
            relief="flat",
            padx=20,
            pady=5
        ).pack(pady=10)
        
        # Bulk QR Code Section
        bulk_frame = tk.LabelFrame(
            main_frame,
            text="Bulk QR Code for MAT",
            font=self.style["title_font"],
            bg=self.style["frame_bg"],
            fg=self.style["fg"],
            padx=10,
            pady=10
        )
        bulk_frame.pack(fill="x", pady=10)
        
        tk.Button(
            bulk_frame,
            text="Upload CSV for MAT QR Codes",
            command=self.generate_bulk_qr,
            bg=self.style["button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["button_active"],
            relief="flat",
            padx=20,
            pady=5
        ).pack(pady=5)
        
        tk.Button(
            bulk_frame,
            text="Preview Bulk QR Codes",
            command=self.preview_bulk_qr,
            bg=self.style["preview_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["preview_button_active"],
            relief="flat",
            padx=20,
            pady=5,
            state="disabled"
        ).pack(pady=5)
        
        # Bulk Navigation Frame
        nav_frame = tk.Frame(bulk_frame, bg=self.style["frame_bg"])
        nav_frame.pack(fill="x", pady=5)
        
        self.prev_button = tk.Button(
            nav_frame,
            text="Previous",
            command=self.show_prev_qr,
            bg=self.style["nav_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["nav_button_active"],
            relief="flat",
            padx=10,
            pady=5,
            state="disabled"
        )
        self.prev_button.pack(side="left", padx=5)
        
        self.next_button = tk.Button(
            nav_frame,
            text="Next",
            command=self.show_next_qr,
            bg=self.style["nav_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["nav_button_active"],
            relief="flat",
            padx=10,
            pady=5,
            state="disabled"
        )
        self.next_button.pack(side="left", padx=5)
        
        # Online Features Section
        online_frame = tk.LabelFrame(
            main_frame,
            text="Online Features",
            font=self.style["title_font"],
            bg=self.style["frame_bg"],
            fg=self.style["fg"],
            padx=10,
            pady=10
        )
        online_frame.pack(fill="x", pady=10)
        
        tk.Label(
            online_frame,
            text="Server URL (e.g., http://localhost:5000):",
            font=self.style["label_font"],
            bg=self.style["frame_bg"]
        ).pack(anchor="w", pady=5)
        
        self.server_url_var = tk.StringVar(value="http://localhost:5000")
        tk.Entry(
            online_frame,
            textvariable=self.server_url_var,
            width=40,
            font=self.style["font"],
            bg="#E6F0FA",
            highlightthickness=1,
            highlightbackground="#B0BEC5"
        ).pack(pady=5, padx=10, ipady=5)
        
        tk.Button(
            online_frame,
            text="Upload QR Code to Server",
            command=self.upload_qr_to_server,
            bg=self.style["online_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["online_button_active"],
            relief="flat",
            padx=20,
            pady=5
        ).pack(side="left", padx=5, pady=5)
        
        tk.Button(
            online_frame,
            text="Verify QR Code Online",
            command=self.verify_qr_online,
            bg=self.style["online_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["online_button_active"],
            relief="flat",
            padx=20,
            pady=5
        ).pack(side="left", padx=5, pady=5)
        
        # QR Code Display and Controls
        control_frame = tk.Frame(main_frame, bg=self.style["frame_bg"])
        control_frame.pack(fill="x", pady=10)
        
        tk.Label(
            control_frame,
            text="QR Code Hash:",
            font=self.style["label_font"],
            bg=self.style["frame_bg"]
        ).pack(anchor="w", pady=5)
        
        self.hash_label = tk.Label(
            control_frame,
            text="No QR code generated",
            font=self.style["label_font"],
            bg=self.style["frame_bg"],
            fg="#424242",
            wraplength=550
        )
        self.hash_label.pack(anchor="w", pady=5)
        
        # Copy Hash Button
        self.copy_hash_button = tk.Button(
            control_frame,
            text="Copy Hash",
            command=self.copy_hash,
            bg=self.style["copy_button_bg"],
            fg=self.style["copy_button_fg"],
            font=self.style["font"],
            activebackground=self.style["copy_button_active"],
            relief="flat",
            padx=10,
            pady=5,
            state="disabled"
        ).pack(anchor="w", pady=5)
        
        # Verify Source Button
        self.verify_button = tk.Button(
            control_frame,
            text="Verify Source",
            command=self.verify_source,
            bg=self.style["verify_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["verify_button_active"],
            relief="flat",
            padx=10,
            pady=5,
            state="disabled"
        )
        self.verify_button.pack(anchor="w", pady=5)
        
        # Report Phishing Button
        self.report_button = tk.Button(
            control_frame,
            text="Report Phishing",
            command=self.report_phishing,
            bg=self.style["report_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["report_button_active"],
            relief="flat",
            padx=10,
            pady=5,
            state="disabled"
        )
        self.report_button.pack(anchor="w", pady=5)
        
        # Buttons Frame
        button_frame = tk.Frame(main_frame, bg=self.style["frame_bg"])
        button_frame.pack(fill="x", pady=10)
        
        tk.Button(
            button_frame,
            text="Select QR to Destroy",
            command=self.select_and_destroy_qr,
            bg=self.style["destroy_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["destroy_button_active"],
            relief="flat",
            padx=20,
            pady=5
        ).pack(side="left", padx=5)
        
        tk.Button(
            button_frame,
            text="Read QR Hash",
            command=self.read_and_display_qr,
            bg=self.style["read_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["read_button_active"],
            relief="flat",
            padx=20,
            pady=5
        ).pack(side="left", padx=5)
        
        tk.Button(
            button_frame,
            text="Change QR Data",
            command=self.change_qr_data,
            bg=self.style["change_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["change_button_active"],
            relief="flat",
            padx=20,
            pady=5
        ).pack(side="left", padx=5)
        
        self.save_button = tk.Button(
            button_frame,
            text="Save QR Code",
            command=self.save_qr,
            bg=self.style["button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["button_active"],
            relief="flat",
            padx=20,
            pady=5,
            state="disabled"
        )
        self.save_button.pack(side="left", padx=5)
        
        self.export_button = tk.Button(
            button_frame,
            text="Export QR Data to CSV",
            command=self.export_qr_data,
            bg=self.style["export_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["export_button_active"],
            relief="flat",
            padx=20,
            pady=5,
            state="disabled"
        )
        self.export_button.pack(side="left", padx=5)
        
        self.history_button = tk.Button(
            button_frame,
            text="Export Scan History",
            command=self.export_scan_history,
            bg=self.style["history_button_bg"],
            fg=self.style["button_fg"],
            font=self.style["font"],
            activebackground=self.style["history_button_active"],
            relief="flat",
            padx=20,
            pady=5,
            state="disabled"
        )
        self.history_button.pack(side="left", padx=5)
        
        # Image Display
        self.image_label = tk.Label(main_frame, bg=self.style["frame_bg"])
        self.image_label.pack(pady=20)
        
        # Features Section
        features_frame = tk.LabelFrame(
            main_frame,
            text="Software Features",
            font=self.style["title_font"],
            bg=self.style["frame_bg"],
            fg=self.style["fg"],
            padx=10,
            pady=10
        )
        features_frame.pack(fill="x", pady=10)
        
        features_text = (
            "• Generate single QR codes with secure hashing\n"
            "• Customize QR code version, error correction, colors, and size\n"
            "• Add text annotations to QR codes\n"
            f"• Encrypt QR code data with a password {'(requires cryptography library)' if not CRYPTOGRAPHY_AVAILABLE else ''}\n"
            "• Generate bulk QR codes for MAT from CSV files\n"
            "• Preview bulk QR codes in a grid view\n"
            "• Navigate through bulk QR code previews\n"
            "• Upload QR codes to a server for online storage\n"
            "• Verify QR codes online by hash\n"
            "• Read and verify QR code data and hash\n"
            "• Destroy QR codes securely\n"
            "• Change QR code data (including dynamic QR codes)\n"
            "• Copy QR code hash to clipboard\n"
            "• Save QR codes as PNG files\n"
            "• Export QR code data and scan history to CSV\n"
            "• Phishing prevention: URL validation and blocklist checking\n"
            "• Digital signatures for QR code authenticity\n"
            "• Scan history logging and phishing reporting\n\n"
            "CSV Format for MAT QR Codes:\n"
            "  - Required Columns:\n"
            "    • student_id: Unique identifier for the student (e.g., S001)\n"
            "    • answers: String of answers (e.g., A,B,C,D)\n"
            "  - Optional Column:\n"
            "    • name: Student's name (e.g., John Doe)\n"
            "  - Example CSV:\n"
            "    student_id,name,answers\n"
            "    S001,John Doe,A,B,C,D\n"
            "    S002,Jane Smith,B,C,D,A\n"
            "    S003,,C,D,A,B"
        )
        tk.Label(
            features_frame,
            text=features_text,
            font=("Helvetica", 10),
            bg=self.style["frame_bg"],
            fg="#333333",
            justify="left"
        ).pack(anchor="w", pady=5)
        
        # Initialize preview button state
        self.preview_button = bulk_frame.winfo_children()[1]  # Second button in bulk_frame
        self.update_preview_button()
        
    def validate_url(self, url):
        """Validate a URL against phishing patterns and blocklist."""
        try:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check blocklist
            if domain in self.phishing_blocklist:
                return False, "URL is on a known phishing blocklist"
            
            # Check for suspicious patterns
            suspicious_patterns = [
                r"login", r"signin", r"microsoftonline", r"sharepoint", r"docusign", r"adobe",
                r"\.zip$", r"\.top$", r"me-qr\.com"  # Common quishing domains
            ]
            for pattern in suspicious_patterns:
                if re.search(pattern, url.lower()):
                    return False, f"URL contains suspicious pattern: {pattern}"
            
            # Check for URL shorteners
            shorteners = ["bit.ly", "tinyurl.com", "t.co"]
            if any(shortener in domain for shortener in shorteners):
                return False, "URL uses a URL shortener, which may hide malicious destinations"
            
            # Check domain age or reputation (simulated; use Google Safe Browsing API in production)
            if "recently-registered" in domain:  # Placeholder for actual API check
                return False, "URL is from a recently registered domain"
            
            return True, "URL appears safe"
        except Exception as e:
            return False, f"Failed to validate URL: {str(e)}"
    
    def sign_qr_data(self, data):
        """Sign QR code data with private key."""
        if not CRYPTOGRAPHY_AVAILABLE:
            return None
        try:
            signature = self.private_key.sign(
                data.encode(),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return base64.b64encode(signature).decode('utf-8')
        except:
            return None
    
    def verify_qr_signature(self, data, signature_b64):
        """Verify QR code signature with public key."""
        if not CRYPTOGRAPHY_AVAILABLE or not signature_b64:
            return False
        try:
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(
                signature,
                data.encode(),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
    
    def log_scan(self, filename, data, url=None):
        """Log QR code scan details."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "filename": filename,
            "data": data,
            "url": url if url else "N/A"
        }
        self.scan_history.append(log_entry)
        self.update_history_button()
    
    def report_phishing(self):
        """Report a suspicious QR code."""
        if not self.qr_filename or not self.qr_hash:
            messagebox.showerror("Error", "No QR code available to report")
            return
        filename, data, qr_hash = self.bulk_qr_data[self.current_bulk_index] if self.bulk_qr_data else (self.qr_filename, "", self.qr_hash)
        report = f"Suspicious QR Code Report:\nFilename: {filename}\nData: {data}\nHash: {qr_hash}"
        # In production, send to a security team or external service
        with open("phishing_report.txt", "a") as f:
            f.write(f"{report}\n{'-'*50}\n")
        messagebox.showinfo("Success", "QR code reported as potential phishing attempt")
    
    def verify_source(self):
        """Verify the source of the current QR code."""
        if not self.qr_filename or not self.qr_hash:
            messagebox.showerror("Error", "No QR code available to verify")
            return
        filename, data, qr_hash = self.bulk_qr_data[self.current_bulk_index] if self.bulk_qr_data else (self.qr_filename, "", self.qr_hash)
        is_url = bool(re.match(r'^https?://', data))
        if not is_url:
            messagebox.showinfo("Verification", "No URL to verify in QR code data")
            return
        is_safe, message = self.validate_url(data)
        if is_safe:
            messagebox.showinfo("Verification", f"Source verified: {message}\nURL: {data}")
        else:
            messagebox.showwarning("Phishing Alert", f"Potential phishing risk: {message}\nURL: {data}\nDo not visit this URL.")
    
    def check_encryption(self):
        if self.encrypt_var.get() and not CRYPTOGRAPHY_AVAILABLE:
            self.encrypt_var.set(False)
            messagebox.showerror("Error", "Encryption requires the 'cryptography' library. Install it using 'pip install cryptography'.")
    
    def encrypt_data(self, data, password):
        if not CRYPTOGRAPHY_AVAILABLE:
            return data
        key = hashlib.sha256(password.encode()).digest()
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted).decode('utf-8')
    
    def decrypt_data(self, encrypted_data, password):
        if not CRYPTOGRAPHY_AVAILABLE:
            return None
        try:
            key = hashlib.sha256(password.encode()).digest()
            encrypted_bytes = base64.b64decode(encrypted_data)
            iv, ciphertext = encrypted_bytes[:16], encrypted_bytes[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            return decrypted.decode('utf-8')
        except:
            return None
    
    def copy_hash(self):
        if self.qr_hash:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.qr_hash)
            messagebox.showinfo("Success", "Hash copied to clipboard")
        else:
            messagebox.showerror("Error", "No hash available to copy")
    
    def upload_qr_to_server(self):
        if not self.bulk_qr_data:
            messagebox.showerror("Error", "No QR codes available to upload")
            return
        server_url = self.server_url_var.get()
        if not server_url:
            messagebox.showerror("Error", "Please enter a server URL")
            return
        try:
            for filename, data, qr_hash in self.bulk_qr_data:
                with open(filename, "rb") as f:
                    image_data = base64.b64encode(f.read()).decode('utf-8')
                payload = {
                    "filename": filename,
                    "data": data,
                    "hash": qr_hash,
                    "image": image_data
                }
                response = requests.post(f"{server_url}/upload", json=payload)
                if response.status_code != 200:
                    messagebox.showerror("Error", f"Failed to upload {filename}: {response.text}")
                    return
            messagebox.showinfo("Success", f"Uploaded {len(self.bulk_qr_data)} QR codes to server")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Network error: {str(e)}")
    
    def verify_qr_online(self):
        server_url = self.server_url_var.get()
        if not server_url:
            messagebox.showerror("Error", "Please enter a server URL")
            return
        hash_input = simpledialog.askstring("Input", "Enter the QR code hash to verify:")
        if not hash_input:
            messagebox.showerror("Error", "Hash is required")
            return
        try:
            response = requests.get(f"{server_url}/get_qr/{hash_input}")
            if response.status_code == 200:
                qr_data = response.json()
                filename = qr_data["filename"]
                data = qr_data["data"]
                qr_hash = qr_data["hash"]
                image_data = base64.b64decode(qr_data["image"])
                with open("temp_qr.png", "wb") as f:
                    f.write(image_data)
                self.qr_filename = "temp_qr.png"
                self.qr_hash = qr_hash
                self.bulk_qr_data = [(self.qr_filename, data, qr_hash)]
                self.current_bulk_index = 0
                self.hash_label.config(text=f"Hash: {qr_hash}")
                self.display_image(self.qr_filename)
                self.save_button.config(state="normal")
                self.copy_hash_button.config(state="normal")
                self.verify_button.config(state="normal")
                self.report_button.config(state="normal")
                self.prev_button.config(state="disabled")
                self.next_button.config(state="disabled")
                self.update_export_button()
                self.update_preview_button()
                messagebox.showinfo("Success", f"QR Data: {data}\nHash: {qr_hash}\nFilename: {filename}")
            else:
                messagebox.showerror("Error", f"Failed to retrieve QR code: {response.text}")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Error", f"Network error: {str(e)}")
    
    def generate_secure_qr(self, data, filename="secure_qr.png", version=1, error_correction="H", annotation=None):
        if self.encrypt_var.get():
            if not CRYPTOGRAPHY_AVAILABLE:
                messagebox.showerror("Error", "Encryption requires the 'cryptography' library. Install it using 'pip install cryptography'.")
                return None, None
            password = simpledialog.askstring("Input", "Enter encryption password:", show="*")
            if not password:
                messagebox.showerror("Error", "Password is required for encryption")
                return None, None
            data = self.encrypt_data(data, password)
        
        # Validate URL if data is a URL
        is_url = bool(re.match(r'^https?://', data))
        if is_url:
            is_safe, message = self.validate_url(data)
            if not is_safe:
                messagebox.showwarning("Phishing Alert", f"Potential phishing risk: {message}\nURL: {data}\nProceed with caution.")
                if not messagebox.askyesno("Confirm", "Do you want to generate this QR code despite the warning?"):
                    return None, None
        
        # Sign data
        signature = self.sign_qr_data(data)
        if signature:
            data = f"{data}|SIG:{signature}"
        
        key = secrets.token_bytes(16)
        data_bytes = data.encode('utf-8')
        hasher = hashlib.sha256()
        hasher.update(data_bytes + key)
        hashed_data = hasher.hexdigest()
        encoded_data = base64.b64encode(data_bytes + b'|' + key).decode('utf-8')
        error_levels = {
            "L": qrcode.constants.ERROR_CORRECT_L,
            "M": qrcode.constants.ERROR_CORRECT_M,
            "Q": qrcode.constants.ERROR_CORRECT_Q,
            "H": qrcode.constants.ERROR_CORRECT_H
        }
        qr = qrcode.QRCode(
            version=min(max(int(version), 1), 40),
            error_correction=error_levels.get(error_correction, qrcode.constants.ERROR_CORRECT_H),
            box_size=10,
            border=4,
        )
        qr.add_data(encoded_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color=self.fill_color_var.get(), back_color=self.back_color_var.get())
        
        # Handle size customization
        size_map = {"Small": 200, "Medium": 300, "Large": 400}
        base_size = size_map.get(self.size_var.get(), 300)
        
        # Add annotation if provided
        if annotation:
            img_size = img.size[0]
            text_height = 40
            new_img = Image.new('RGB', (img_size, img_size + text_height), color=self.back_color_var.get())
            new_img.paste(img, (0, 0))
            draw = ImageDraw.Draw(new_img)
            try:
                font = ImageFont.truetype("arial.ttf", 20)
            except:
                font = ImageFont.load_default()
            text_width = draw.textlength(annotation, font=font)
            text_x = (img_size - text_width) / 2
            draw.text((text_x, img_size + 10), annotation, fill=self.fill_color_var.get(), font=font)
            img = new_img
        
        img = img.resize((base_size, base_size + (40 if annotation else 0)), Image.LANCZOS)
        img.save(filename)
        
        # Log scan
        self.log_scan(filename, data, data if is_url else None)
        
        return filename, hashed_data
    
    def read_qr_code(self, image_path):
        img = cv2.imread(image_path)
        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)
        
        if not data:
            return None, None
        
        try:
            # Try to decode as base64 (your app's format)
            decoded_bytes = base64.b64decode(data)
            data_parts = decoded_bytes.split(b'|')
            
            if len(data_parts) >= 2:  # Your app's format with key and optional signature
                original_data = data_parts[0].decode('utf-8')
                key = data_parts[-1]
                signature = None
                
                # Check for signature if present
                if len(data_parts) > 2 and data_parts[1].startswith(b'SIG:'):
                    signature = data_parts[1].decode('utf-8').replace('SIG:', '')
                
                # Verify signature if present
                if signature and not self.verify_qr_signature(original_data, signature):
                    messagebox.showwarning("Security Alert", "QR code signature verification failed. This code may have been tampered with.")
                    return None, None
                
                # Check if data is encrypted
                try:
                    base64.b64decode(original_data)
                    if not CRYPTOGRAPHY_AVAILABLE:
                        messagebox.showerror("Error", "Decryption requires the 'cryptography' library. Install it using 'pip install cryptography'.")
                        return None, None
                    password = simpledialog.askstring("Input", "Enter decryption password:", show="*")
                    if password:
                        decrypted_data = self.decrypt_data(original_data, password)
                        if decrypted_data:
                            original_data = decrypted_data
                        else:
                            return None, None
                    else:
                        return None, None
                except:
                    pass
                
                hasher = hashlib.sha256()
                hasher.update(original_data.encode() + key)
                hashed_data = hasher.hexdigest()
            else:
                # Handle plain text or third-party QR codes
                original_data = data
                hasher = hashlib.sha256()
                hasher.update(original_data.encode())
                hashed_data = hasher.hexdigest()
            
            # Validate URL if present
            is_url = bool(re.match(r'^https?://', original_data))
            if is_url:
                is_safe, message = self.validate_url(original_data)
                if not is_safe:
                    messagebox.showwarning("Phishing Alert", f"Potential phishing risk: {message}\nURL: {original_data}\nProceed with caution.")
            
            # Log scan
            self.log_scan(image_path, original_data, original_data if is_url else None)
            
            return original_data, hashed_data
        
        except base64.binascii.Error:
            # Handle non-base64 encoded data (third-party QR codes)
            original_data = data
            hasher = hashlib.sha256()
            hasher.update(original_data.encode())
            hashed_data = hasher.hexdigest()
            
            # Validate URL if present
            is_url = bool(re.match(r'^https?://', original_data))
            if is_url:
                is_safe, message = self.validate_url(original_data)
                if not is_safe:
                    messagebox.showwarning("Phishing Alert", f"Potential phishing risk: {message}\nURL: {original_data}\nProceed with caution.")
            
            # Log scan
            self.log_scan(image_path, original_data, original_data if is_url else None)
            
            return original_data, hashed_data
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to process QR code: {str(e)}")
            return None, None
    
    def destroy_qr_code(self, image_path, hashed_data, output_path="destroyed_qr.png"):
        original_data, original_hash = self.read_qr_code(image_path)
        if not original_data or original_hash != hashed_data:
            return False, "Invalid QR code or hash mismatch"
        img = Image.open(image_path).convert('RGB')
        img_array = np.array(img, dtype=np.uint8)
        noise = np.random.randint(0, 255, img_array.shape, dtype=np.uint8)
        destroyed = cv2.addWeighted(img_array, 0.6, noise, 0.4, 0)
        cv2.imwrite(output_path, destroyed)
        destroyed_data, _ = self.read_qr_code(output_path)
        if destroyed_data:
            return False, "Failed to destroy QR code"
        return True, output_path
    
    def change_qr_data(self):
        file_path = filedialog.askopenfilename(filetypes=[("PNG files", "*.png")])
        if not file_path:
            return
        hash_input = simpledialog.askstring("Input", "Enter the QR code hash:")
        if not hash_input:
            messagebox.showerror("Error", "Hash is required")
            return
        original_data, original_hash = self.read_qr_code(file_path)
        if not original_data or original_hash != hash_input:
            messagebox.showerror("Error", "Invalid QR code or hash mismatch")
            return
        is_url = bool(re.match(r'^https?://', original_data))
        prompt = "Enter new data for QR code (URL detected):" if is_url else "Enter new data for QR code:"
        new_data = simpledialog.askstring("Input", prompt, initialvalue=original_data)
        if not new_data:
            messagebox.showerror("Error", "New data is required")
            return
        version = self.version_var.get()
        error_correction = self.error_var.get()
        annotation = self.annotation_entry.get()
        self.qr_filename, self.qr_hash = self.generate_secure_qr(
            new_data, "updated_qr.png", version, error_correction, annotation
        )
        if self.qr_filename:
            self.bulk_qr_data = [(self.qr_filename, new_data, self.qr_hash)]
            self.current_bulk_index = 0
            self.hash_label.config(text=f"Hash: {self.qr_hash}")
            self.display_image(self.qr_filename)
            self.save_button.config(state="normal")
            self.copy_hash_button.config(state="normal")
            self.verify_button.config(state="normal")
            self.report_button.config(state="normal")
            self.prev_button.config(state="disabled")
            self.next_button.config(state="disabled")
            self.update_export_button()
            self.update_preview_button()
            messagebox.showinfo("Success", f"QR code data updated: {self.qr_filename}")
    
    def generate_qr(self):
        data = self.data_entry.get()
        if not data:
            messagebox.showerror("Error", "Please enter data for the QR code")
            return
        version = self.version_var.get()
        error_correction = self.error_var.get()
        annotation = self.annotation_entry.get()
        self.qr_filename, self.qr_hash = self.generate_secure_qr(
            data, version=version, error_correction=error_correction, annotation=annotation
        )
        if self.qr_filename:
            self.bulk_qr_data = [(self.qr_filename, data, self.qr_hash)]
            self.current_bulk_index = 0
            self.hash_label.config(text=f"Hash: {self.qr_hash}")
            self.display_image(self.qr_filename)
            self.save_button.config(state="normal")
            self.copy_hash_button.config(state="normal")
            self.verify_button.config(state="normal")
            self.report_button.config(state="normal")
            self.prev_button.config(state="disabled")
            self.next_button.config(state="disabled")
            self.update_export_button()
            self.update_preview_button()
            messagebox.showinfo("Success", f"QR code generated: {self.qr_filename}")
    
    def generate_bulk_qr(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not file_path:
            return
        try:
            df = pd.read_csv(file_path)
            required_columns = ['student_id', 'answers']
            if not all(col in df.columns for col in required_columns):
                messagebox.showerror("Error", "CSV must contain 'student_id' and 'answers' columns")
                return
            zip_filename = f"mat_qr_codes_{uuid.uuid4().hex}.zip"
            self.bulk_qr_data = []
            self.current_bulk_index = 0
            with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for index, row in df.iterrows():
                    student_id = str(row['student_id'])
                    answers = str(row['answers'])
                    name = str(row['name']) if 'name' in df.columns else ''
                    data = f"{student_id}:{name}:{answers}" if name else f"{student_id}::{answers}"
                    annotation = f"Student ID: {student_id}" if name else student_id
                    if student_id and answers:
                        qr_filename = f"qr_{student_id}.png"
                        qr_filename, qr_hash = self.generate_secure_qr(
                            data, qr_filename, annotation=annotation
                        )
                        if qr_filename:
                            zipf.write(qr_filename, qr_filename)
                            self.bulk_qr_data.append((qr_filename, data, qr_hash))
                            if not self.qr_filename:
                                self.qr_filename = qr_filename
                                self.qr_hash = qr_hash
                                self.display_image(self.qr_filename)
                                self.hash_label.config(text=f"Hash (First QR): {qr_hash}")
                                self.save_button.config(state="normal")
                                self.copy_hash_button.config(state="normal")
                                self.verify_button.config(state="normal")
                                self.report_button.config(state="normal")
                            os.remove(qr_filename)
            if self.bulk_qr_data:
                self.update_export_button()
                self.update_nav_buttons()
                self.update_preview_button()
            messagebox.showinfo("Success", f"Generated {len(self.bulk_qr_data)} MAT QR codes, saved in {zip_filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to process CSV: {str(e)}")
    
    def preview_bulk_qr(self):
        if not self.bulk_qr_data:
            messagebox.showerror("Error", "No bulk QR codes available to preview")
            return
        preview_window = tk.Toplevel(self.root)
        preview_window.title("Bulk QR Code Preview")
        preview_window.geometry("800x600")
        canvas = tk.Canvas(preview_window, bg=self.style["frame_bg"])
        scrollbar = ttk.Scrollbar(preview_window, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.style["frame_bg"])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        cols = 3
        for i, (filename, data, qr_hash) in enumerate(self.bulk_qr_data):
            row = i // cols
            col = i % cols
            img = Image.open(filename)
            img = img.resize((150, 150), Image.LANCZOS)
            photo = ImageTk.PhotoImage(img)
            label = tk.Label(
                scrollable_frame,
                image=photo,
                bg=self.style["frame_bg"],
                text=f"ID: {data.split(':')[0]}\nHash: {qr_hash[:10]}...",
                compound="top",
                font=("Helvetica", 10)
            )
            label.image = photo
            label.grid(row=row, column=col, padx=10, pady=10)
        
        preview_window.transient(self.root)
        preview_window.grab_set()
    
    def export_scan_history(self):
        if not self.scan_history:
            messagebox.showerror("Error", "No scan history available to export")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if save_path:
            try:
                df = pd.DataFrame(self.scan_history)
                df.to_csv(save_path, index=False)
                messagebox.showinfo("Success", f"Scan history exported to {save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export scan history: {str(e)}")
    
    def update_nav_buttons(self):
        if len(self.bulk_qr_data) > 1:
            self.prev_button.config(state="normal" if self.current_bulk_index > 0 else "disabled")
            self.next_button.config(state="normal" if self.current_bulk_index < len(self.bulk_qr_data) - 1 else "disabled")
        else:
            self.prev_button.config(state="disabled")
            self.next_button.config(state="disabled")
    
    def update_export_button(self):
        self.root.after(0, lambda: self.export_button.config(state="normal" if self.bulk_qr_data else "disabled"))
    
    def update_preview_button(self):
        self.root.after(0, lambda: self.preview_button.config(state="normal" if self.bulk_qr_data else "disabled"))
    
    def update_history_button(self):
        self.root.after(0, lambda: self.history_button.config(state="normal" if self.scan_history else "disabled"))
    
    def show_prev_qr(self):
        if self.current_bulk_index > 0:
            self.current_bulk_index -= 1
            filename, data, qr_hash = self.bulk_qr_data[self.current_bulk_index]
            self.qr_filename = filename
            self.qr_hash = qr_hash
            self.display_image(filename)
            self.hash_label.config(text=f"Hash (QR {self.current_bulk_index + 1}/{len(self.bulk_qr_data)}): {qr_hash}")
            self.save_button.config(state="normal")
            self.copy_hash_button.config(state="normal")
            self.verify_button.config(state="normal")
            self.report_button.config(state="normal")
            self.update_nav_buttons()
    
    def show_next_qr(self):
        if self.current_bulk_index < len(self.bulk_qr_data) - 1:
            self.current_bulk_index += 1
            filename, data, qr_hash = self.bulk_qr_data[self.current_bulk_index]
            self.qr_filename = filename
            self.qr_hash = qr_hash
            self.display_image(filename)
            self.hash_label.config(text=f"Hash (QR {self.current_bulk_index + 1}/{len(self.bulk_qr_data)}): {qr_hash}")
            self.save_button.config(state="normal")
            self.copy_hash_button.config(state="normal")
            self.verify_button.config(state="normal")
            self.report_button.config(state="normal")
            self.update_nav_buttons()
    
    def export_qr_data(self):
        if not self.bulk_qr_data:
            messagebox.showerror("Error", "No QR code data available to export")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if save_path:
            try:
                df = pd.DataFrame(self.bulk_qr_data, columns=["filename", "data", "hash"])
                df.to_csv(save_path, index=False)
                messagebox.showinfo("Success", f"QR code data exported to {save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export QR data: {str(e)}")
    
    def save_qr(self):
        if not self.qr_filename or not os.path.exists(self.qr_filename):
            messagebox.showerror("Error", "No QR code available to save")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if save_path:
            try:
                shutil.copy(self.qr_filename, save_path)
                messagebox.showinfo("Success", f"QR code saved to {save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save QR code: {str(e)}")
    
    def select_and_destroy_qr(self):
        file_path = filedialog.askopenfilename(filetypes=[("PNG files", "*.png")])
        if not file_path:
            return
        hash_input = simpledialog.askstring("Input", "Enter the QR code hash:")
        if not hash_input:
            messagebox.showerror("Error", "Hash is required")
            return
        success, result = self.destroy_qr_code(file_path, hash_input)
        if success:
            self.display_image(result)
            self.qr_filename = result
            self.bulk_qr_data = []
            self.current_bulk_index = 0
            self.save_button.config(state="normal")
            self.copy_hash_button.config(state="disabled")
            self.verify_button.config(state="disabled")
            self.report_button.config(state="disabled")
            self.prev_button.config(state="disabled")
            self.next_button.config(state="disabled")
            self.update_export_button()
            self.update_preview_button()
            messagebox.showinfo("Success", "QR code destroyed successfully")
        else:
            messagebox.showerror("Error", result)
    
    def read_and_display_qr(self):
        file_path = filedialog.askopenfilename(filetypes=[("PNG files", "*.png")])
        if not file_path:
            return
        data, hashed_data = self.read_qr_code(file_path)
        if data and hashed_data:
            self.qr_filename = file_path
            self.qr_hash = hashed_data
            self.bulk_qr_data = [(file_path, data, hashed_data)]
            self.current_bulk_index = 0
            self.hash_label.config(text=f"Hash: {hashed_data}")
            self.display_image(file_path)
            self.save_button.config(state="normal")
            self.copy_hash_button.config(state="normal")
            self.verify_button.config(state="normal")
            self.report_button.config(state="normal")
            self.prev_button.config(state="disabled")
            self.next_button.config(state="disabled")
            self.update_export_button()
            self.update_preview_button()
            messagebox.showinfo("Success", f"QR Data: {data}\nHash: {hashed_data}")
        else:
            messagebox.showerror("Error", "Failed to read QR code or invalid QR code")
    
    def display_image(self, image_path):
        img = Image.open(image_path)
        img = img.resize((300, 300), Image.LANCZOS)
        photo = ImageTk.PhotoImage(img)
        self.image_label.config(image=photo)
        self.image_label.image = photo

if __name__ == "__main__":
    root = tk.Tk()
    app = QRCodeApp(root)
    root.mainloop()