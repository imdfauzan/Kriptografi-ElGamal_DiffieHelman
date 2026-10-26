"""
=============================================================================
SISTEM SLIP GAJI DIGITAL TERENKRIPSI BERBASIS ELGAMAL & SIMULATOR DIFFIE-HELLMAN
Mata Kuliah: Kriptografi
Implementasi: Discrete Logarithm Problem (DLP) Murni + GUI Tkinter
Author: Lab Kriptografi
=============================================================================
"""

import sys
import os
import json
import random
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime

# =============================================================================
# BAGIAN 1: CORE MATH ENGINE (DISCRETE LOGARITHM PROBLEM UTILITIES)
# =============================================================================

class DLPEngine:
    """
    Mesin matematika dasar untuk protokol berbasis Discrete Logarithm:
    1. Extended Euclidean Algorithm (Mencari Modular Multiplicative Inverse)
    2. Square-and-Multiply (Modular Exponentiation efisien)
    3. Miller-Rabin Primality Test
    4. Safe Prime & Primitive Root (Generator) Generator
    """

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """Algoritma Euclidean standar untuk Greatest Common Divisor."""
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def extended_gcd(a: int, b: int):
        """
        Extended Euclidean Algorithm:
        Mencari koefisien Bézout x dan y sedemikian hingga: a*x + b*y = gcd(a, b).
        """
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = DLPEngine.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y

    @staticmethod
    def mod_inverse(a: int, m: int) -> int:
        """
        Menghitung modular multiplicative inverse: (a * a_inv) = 1 (mod m).
        Dibutuhkan pada tahap dekripsi ElGamal untuk membatalkan ephemeral key.
        """
        gcd_val, x, _ = DLPEngine.extended_gcd(a, m)
        if gcd_val != 1:
            raise ValueError(f"Invers modulo tidak ada karena gcd({a}, {m}) != 1")
        return (x % m + m) % m

    @staticmethod
    def mod_pow(base: int, exp: int, mod: int) -> int:
        """
        Modular Exponentiation dengan metode Square-and-Multiply:
        Menghitung (base ^ exp) % mod dalam waktu O(log exp), mencegah memory overflow.
        """
        result = 1
        base = base % mod
        while exp > 0:
            if exp % 2 == 1:
                result = (result * base) % mod
            exp = exp // 2
            base = (base * base) % mod
        return result

    @staticmethod
    def is_prime_miller_rabin(n: int, k: int = 15) -> bool:
        """Uji keprimaan Miller-Rabin probabilistik."""
        if n < 2:
            return False
        if n in (2, 3):
            return True
        if n % 2 == 0:
            return False

        # Tulis n - 1 sebagai 2^s * d
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = DLPEngine.mod_pow(a, d, n)
            if x == 1 or x == n - 1:
                continue

            composite = True
            for _ in range(s - 1):
                x = DLPEngine.mod_pow(x, 2, n)
                if x == n - 1:
                    composite = False
                    break
            if composite:
                return False
        return True

    @classmethod
    def generate_safe_prime_and_generator(cls, bits: int = 40):
        """
        Membangkitkan Safe Prime p = 2q + 1 (di mana q juga bilangan prima).
        Keuntungan safe prime: pencarian primitive root g menjadi sangat terukur.
        Faktor dari p-1 hanyalah 2 dan q.
        Sebuah bilangan g adalah primitive root mod p jika:
        1. g^2 != 1 (mod p)
        2. g^q != 1 (mod p)
        """
        while True:
            # Bangkitkan kandidat bilangan prima q (Sophie Germain prime)
            q = random.getrandbits(bits - 1) | (1 << (bits - 2)) | 1
            if not cls.is_prime_miller_rabin(q, k=10):
                continue

            p = 2 * q + 1
            if cls.is_prime_miller_rabin(p, k=15):
                # Cari generator g (primitive root)
                for g in range(2, p):
                    # Uji apakah g membangkitkan full multiplicative group mod p
                    if cls.mod_pow(g, 2, p) != 1 and cls.mod_pow(g, q, p) != 1:
                        return p, g


# =============================================================================
# BAGIAN 2: PROTOKOL DIFFIE-HELLMAN (KEY EXCHANGE ENGINE)
# =============================================================================

class DiffieHellmanEngine:
    """
    Simulasi protokol Diffie-Hellman Key Agreement:
    Menghasilkan shared secret K di antara dua pihak (HRD dan Karyawan)
    di atas saluran komunikasi publik tanpa mentransmisikan nilai rahasia.
    """

    @staticmethod
    def generate_private_key(p: int) -> int:
        """Memilih private key acak x di mana 2 <= x <= p-2."""
        return random.randint(2, p - 2)

    @staticmethod
    def compute_public_key(g: int, priv_key: int, p: int) -> int:
        """Menghitung public key: Y = (g ^ priv_key) mod p."""
        return DLPEngine.mod_pow(g, priv_key, p)

    @staticmethod
    def compute_shared_secret(their_public_key: int, my_private_key: int, p: int) -> int:
        """Menghitung shared secret: K = (their_public ^ my_private) mod p."""
        return DLPEngine.mod_pow(their_public_key, my_private_key, p)


# =============================================================================
# BAGIAN 3: KRIPTOSISTEM ASIMETRIS ELGAMAL (ENCRYPTION & DECRYPTION)
# =============================================================================

class ElGamalEngine:
    """
    Mesin Kriptosistem ElGamal:
    1. Key Generation: public key (p, g, y) dan private key x
    2. Encryption: menghasilkan pasangan ciphertext (c1, c2) dengan ephemeral key k
    3. Decryption: merekonstruksi plaintext dengan shared secret recovery & modular inverse
    4. Chunking: memotong teks slip gaji agar setiap blok integer m_i < p
    """

    @classmethod
    def generate_keypair(cls, bits: int = 40):
        """
        Membangkitkan domain parameters dan keypair ElGamal:
        Domain Parameters : p (prime), g (primitive root)
        Private Key       : x (integer acak 2 <= x <= p-2)
        Public Key        : (p, g, y) di mana y = (g ^ x) mod p
        """
        p, g = DLPEngine.generate_safe_prime_and_generator(bits=bits)
        x = random.randint(2, p - 2)
        y = DLPEngine.mod_pow(g, x, p)
        return p, g, x, y

    @classmethod
    def encrypt_bytes(cls, plaintext_bytes: bytes, p: int, g: int, y: int):
        """
        Enkripsi ElGamal per blok byte:
        Setiap blok m_i dienkripsi menjadi pasangan ciphertext:
        c1 = (g ^ k) mod p
        c2 = (m_i * (y ^ k)) mod p
        """
        # Ukuran blok byte maksimal: (bit_length - 1) // 8
        # Menjamin representasi integer m_i selalu < p
        block_size = max(1, (p.bit_length() - 1) // 8)
        ciphertext_pairs = []
        block_metadata = []

        for i in range(0, len(plaintext_bytes), block_size):
            chunk = plaintext_bytes[i:i + block_size]
            m_int = int.from_bytes(chunk, byteorder='big')

            # Ephemeral key k acak yang relatif prima terhadap (p - 1)
            while True:
                k = random.randint(2, p - 2)
                if DLPEngine.gcd(k, p - 1) == 1:
                    break

            # Hitung komponen c1 dan c2
            c1 = DLPEngine.mod_pow(g, k, p)
            shared_factor = DLPEngine.mod_pow(y, k, p)  # y^k mod p
            c2 = (m_int * shared_factor) % p

            ciphertext_pairs.append((str(c1), str(c2)))
            block_metadata.append({
                "index": i // block_size,
                "byte_len": len(chunk),
                "m_int": m_int,
                "k_nonce": k,
                "c1": c1,
                "c2": c2
            })

        return ciphertext_pairs, block_size, block_metadata

    @classmethod
    def decrypt_bytes(cls, ciphertext_pairs: list, block_sizes: list, p: int, x: int):
        """
        Dekripsi ElGamal per blok byte:
        Shared secret recovery : S = (c1 ^ x) mod p
        Invers shared secret   : S_inv = S^(-1) mod p
        Pemulihan plaintext    : m_i = (c2 * S_inv) mod p
        """
        decrypted_bytes = bytearray()
        trace_blocks = []

        for idx, ((c1_str, c2_str), b_len) in enumerate(zip(ciphertext_pairs, block_sizes)):
            c1 = int(c1_str)
            c2 = int(c2_str)

            # Hitung S dan S invers
            s = DLPEngine.mod_pow(c1, x, p)
            s_inv = DLPEngine.mod_inverse(s, p)

            # Hitung plaintext integer
            m_int = (c2 * s_inv) % p
            chunk = m_int.to_bytes(b_len, byteorder='big')
            decrypted_bytes.extend(chunk)

            trace_blocks.append({
                "index": idx,
                "c1": c1,
                "c2": c2,
                "recovered_s": s,
                "s_inv": s_inv,
                "m_int": m_int,
                "byte_len": b_len
            })

        return bytes(decrypted_bytes), trace_blocks


# =============================================================================
# BAGIAN 4: GRAPHICAL USER INTERFACE (TKINTER APPLICATION)
# =============================================================================

class CryptographyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sistem Distribusi Slip Gaji Terenkripsi (ElGamal & Diffie-Hellman)")
        self.geometry("1100x820")
        self.minsize(980, 720)

        # State Penyimpanan Kunci & Dokumen
        self.elgamal_keys = {
            "p": None, "g": None, "x": None, "y": None
        }
        self.loaded_enc_payload = None

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self.style.configure(".", font=("Segoe UI", 9))
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=[14, 7])
        self.style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"), background="#2563eb", foreground="white")
        self.style.map("Accent.TButton", background=[("active", "#1d4ed8")])
        self.style.configure("Success.TButton", font=("Segoe UI", 9, "bold"), background="#059669", foreground="white")
        self.style.map("Success.TButton", background=[("active", "#047857")])

    def _build_ui(self):
        # Header Banner
        banner = tk.Frame(self, bg="#0f172a", height=75)
        banner.pack(fill=tk.X, side=tk.TOP)
        banner.pack_propagate(False)

        lbl_title = tk.Label(
            banner, text="SECURE PAYROLL SYSTEM (ELGAMAL & DIFFIE-HELLMAN)",
            font=("Segoe UI", 13, "bold"), fg="#38bdf8", bg="#0f172a"
        )
        lbl_title.pack(anchor=tk.W, padx=20, pady=(10, 2))

        lbl_sub = tk.Label(
            banner, text="Implementasi Discrete Logarithm Problem (DLP) Tanpa Library Kriptografi",
            font=("Segoe UI", 9), fg="#94a3b8", bg="#0f172a"
        )
        lbl_sub.pack(anchor=tk.W, padx=20)

        # Main Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        self.tab_dh = ttk.Frame(self.notebook, padding=12)
        self.tab_karyawan = ttk.Frame(self.notebook, padding=12)
        self.tab_hrd = ttk.Frame(self.notebook, padding=12)
        self.tab_inspector = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.tab_dh, text=" 🤝 Simulasi Diffie-Hellman ")
        self.notebook.add(self.tab_karyawan, text=" 👤 Portal Karyawan (ElGamal) ")
        self.notebook.add(self.tab_hrd, text=" 🏢 Portal HRD (Enkripsi) ")
        self.notebook.add(self.tab_inspector, text=" 🔬 DLP Math Inspector ")

        self._build_dh_tab()
        self._build_karyawan_tab()
        self._build_hrd_tab()
        self._build_inspector_tab()

    # -------------------------------------------------------------------------
    # TAB 1: SIMULATOR DIFFIE-HELLMAN KEY EXCHANGE
    # -------------------------------------------------------------------------
    def _build_dh_tab(self):
        root_pane = ttk.Frame(self.tab_dh)
        root_pane.pack(fill=tk.BOTH, expand=True)

        grp_params = ttk.LabelFrame(root_pane, text=" 1. Domain Parameters Publik (Disepakati Bersama) ", padding=10)
        grp_params.pack(fill=tk.X, pady=(0, 10))

        btn_dh_gen = ttk.Button(grp_params, text="🎲 Bangkitkan Parameter Publik Baru (p & g)", style="Accent.TButton",
                                command=self._handle_dh_generate_params)
        btn_dh_gen.pack(anchor=tk.W, pady=(0, 6))

        params_grid = ttk.Frame(grp_params)
        params_grid.pack(fill=tk.X)

        ttk.Label(params_grid, text="Prime Modulus (p):").grid(row=0, column=0, sticky=tk.W, padx=4)
        self.ent_dh_p = ttk.Entry(params_grid, font=("Consolas", 9))
        self.ent_dh_p.grid(row=0, column=1, sticky=tk.EW, padx=4, pady=2)

        ttk.Label(params_grid, text="Primitive Root (g):").grid(row=1, column=0, sticky=tk.W, padx=4)
        self.ent_dh_g = ttk.Entry(params_grid, font=("Consolas", 9))
        self.ent_dh_g.grid(row=1, column=1, sticky=tk.EW, padx=4, pady=2)
        params_grid.columnconfigure(1, weight=1)

        # Dua Kolom Entitas: HRD (Alice) & Karyawan (Bob)
        paned = ttk.PanedWindow(root_pane, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        col_alice = ttk.LabelFrame(paned, text=" Pihak HRD (Alice) ", padding=10)
        col_bob = ttk.LabelFrame(paned, text=" Pihak Karyawan (Bob) ", padding=10)
        paned.add(col_alice, weight=1)
        paned.add(col_bob, weight=1)

        # Alice Form
        ttk.Label(col_alice, text="Private Key Alice (a):").pack(anchor=tk.W)
        self.ent_dh_alice_priv = ttk.Entry(col_alice, font=("Consolas", 9))
        self.ent_dh_alice_priv.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(col_alice, text="Public Key Alice (A = g^a mod p):").pack(anchor=tk.W)
        self.ent_dh_alice_pub = ttk.Entry(col_alice, font=("Consolas", 9), state="readonly")
        self.ent_dh_alice_pub.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(col_alice, text="Hasil Shared Secret di Alice (K_A = B^a mod p):").pack(anchor=tk.W)
        self.ent_dh_alice_secret = ttk.Entry(col_alice, font=("Consolas", 9, "bold"), foreground="#059669", state="readonly")
        self.ent_dh_alice_secret.pack(fill=tk.X, pady=(2, 6))

        # Bob Form
        ttk.Label(col_bob, text="Private Key Bob (b):").pack(anchor=tk.W)
        self.ent_dh_bob_priv = ttk.Entry(col_bob, font=("Consolas", 9))
        self.ent_dh_bob_priv.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(col_bob, text="Public Key Bob (B = g^b mod p):").pack(anchor=tk.W)
        self.ent_dh_bob_pub = ttk.Entry(col_bob, font=("Consolas", 9), state="readonly")
        self.ent_dh_bob_pub.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(col_bob, text="Hasil Shared Secret di Bob (K_B = A^b mod p):").pack(anchor=tk.W)
        self.ent_dh_bob_secret = ttk.Entry(col_bob, font=("Consolas", 9, "bold"), foreground="#059669", state="readonly")
        self.ent_dh_bob_secret.pack(fill=tk.X, pady=(2, 6))

        # Action Bottom Bar
        act_bar = ttk.Frame(root_pane)
        act_bar.pack(fill=tk.X)

        ttk.Button(act_bar, text="🚀 Jalankan Handshake Diffie-Hellman", style="Success.TButton",
                   command=self._handle_dh_execute_handshake).pack(side=tk.LEFT, padx=(0, 10))
        self.lbl_dh_status = ttk.Label(act_bar, text="Status: Belum dieksekusi", font=("Segoe UI", 9, "bold"))
        self.lbl_dh_status.pack(side=tk.LEFT)

    # -------------------------------------------------------------------------
    # TAB 2: PORTAL KARYAWAN (ELGAMAL)
    # -------------------------------------------------------------------------
    def _build_karyawan_tab(self):
        paned = ttk.PanedWindow(self.tab_karyawan, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        left_side = ttk.Frame(paned, padding=(0, 0, 8, 0))
        right_side = ttk.Frame(paned, padding=(8, 0, 0, 0))
        paned.add(left_side, weight=1)
        paned.add(right_side, weight=1)

        # 1. Key Generator ElGamal
        grp_karyawan_key = ttk.LabelFrame(left_side, text=" 1. Key Management Karyawan (ElGamal) ", padding=10)
        grp_karyawan_key.pack(fill=tk.X, pady=(0, 10))

        bar_key = ttk.Frame(grp_karyawan_key)
        bar_key.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(bar_key, text="🔑 Generate Keypair ElGamal", style="Accent.TButton",
                   command=self._handle_elgamal_generate_keys).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(bar_key, text="💾 Simpan Kunci", command=self._handle_save_elgamal_keys).pack(side=tk.LEFT)

        ttk.Label(grp_karyawan_key, text="Public Key Karyawan (p, g, y):").pack(anchor=tk.W)
        self.txt_elgamal_pub = tk.Text(grp_karyawan_key, height=4, font=("Consolas", 8), bg="#f8fafc", wrap=tk.CHAR)
        self.txt_elgamal_pub.pack(fill=tk.X, pady=(2, 6))

        ttk.Label(grp_karyawan_key, text="Private Key Karyawan (x):").pack(anchor=tk.W)
        self.txt_elgamal_priv = tk.Text(grp_karyawan_key, height=2, font=("Consolas", 8), bg="#fef2f2", wrap=tk.CHAR)
        self.txt_elgamal_priv.pack(fill=tk.X, pady=(2, 4))

        # 2. Dekripsi Dokumen Slip Gaji
        grp_dec = ttk.LabelFrame(left_side, text=" 2. Dekripsi Berkas Slip Gaji (.enc) ", padding=10)
        grp_dec.pack(fill=tk.BOTH, expand=True)

        ttk.Button(grp_dec, text="📂 Load Berkas .enc", command=self._handle_load_enc_file).pack(anchor=tk.W, pady=(0, 6))
        self.lbl_enc_info = ttk.Label(grp_dec, text="Status berkas: Belum dimuat", foreground="#64748b")
        self.lbl_enc_info.pack(anchor=tk.W, pady=(0, 6))

        ttk.Label(grp_dec, text="Prime Modulus (p):").pack(anchor=tk.W)
        self.ent_dec_p = ttk.Entry(grp_dec, font=("Consolas", 9))
        self.ent_dec_p.pack(fill=tk.X, pady=(2, 4))

        ttk.Label(grp_dec, text="Private Key Karyawan (x):").pack(anchor=tk.W)
        self.ent_dec_x = ttk.Entry(grp_dec, font=("Consolas", 9))
        self.ent_dec_x.pack(fill=tk.X, pady=(2, 10))

        ttk.Button(grp_dec, text="🔓 Dekripsi Slip Gaji", style="Success.TButton",
                   command=self._handle_elgamal_decrypt).pack(fill=tk.X, ipady=4)

        # 3. Payslip Display Card (Sisi Kanan)
        grp_card = ttk.LabelFrame(right_side, text=" 3. Tampilan Hasil Dekripsi Slip Gaji ", padding=10)
        grp_card.pack(fill=tk.BOTH, expand=True)

        self.txt_slip_output = tk.Text(grp_card, font=("Courier New", 9), bg="#ffffff", fg="#0f172a", wrap=tk.NONE)
        scroll_slip = ttk.Scrollbar(grp_card, orient=tk.VERTICAL, command=self.txt_slip_output.yview)
        self.txt_slip_output.configure(yscrollcommand=scroll_slip.set)
        scroll_slip.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_slip_output.pack(fill=tk.BOTH, expand=True)
        self._display_blank_payroll()

    # -------------------------------------------------------------------------
    # TAB 3: PORTAL HRD (ENKRIPSI ELGAMAL)
    # -------------------------------------------------------------------------
    def _build_hrd_tab(self):
        container = ttk.Frame(self.tab_hrd)
        container.pack(fill=tk.BOTH, expand=True)

        left_col = ttk.LabelFrame(container, text=" Form Data Slip Gaji ", padding=10)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        entries = [
            ("NIK Karyawan", "nik", "IT-2024-001"),
            ("Nama Lengkap", "nama", "Imam Mahmud Dalil Fauzan"),
            ("Jabatan / Posisi", "jabatan", "IT Infrastructure Specialist"),
            ("Periode Penggajian", "periode", "Oktober 2026"),
            ("Gaji Pokok (Rp)", "gaji_pokok", "12500000"),
            ("Tunjangan Operasional (Rp)", "tunjangan", "3500000"),
            ("Potongan BPJS (Rp)", "potongan_bpjs", "450000"),
            ("Potongan Pajak PPh 21 (Rp)", "potongan_pph", "650000"),
            ("Catatan HRD", "catatan", "Kinerja kuartal ketiga sangat baik.")
        ]

        self.hrd_entries = {}
        for idx, (label_txt, key_name, default_val) in enumerate(entries):
            ttk.Label(left_col, text=label_txt + ":").grid(row=idx, column=0, sticky=tk.W, padx=4, pady=3)
            entry = ttk.Entry(left_col, font=("Segoe UI", 9))
            entry.insert(0, default_val)
            entry.grid(row=idx, column=1, sticky=tk.EW, padx=4, pady=3)
            self.hrd_entries[key_name] = entry
        left_col.columnconfigure(1, weight=1)

        # Sisi Kanan: Target Public Key & Enkripsi
        right_col = ttk.Frame(container)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(8, 0))

        grp_target = ttk.LabelFrame(right_col, text=" Public Key Karyawan Tujuan ", padding=10)
        grp_target.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(grp_target, text="Modulus Prima (p):").pack(anchor=tk.W)
        self.ent_hrd_p = ttk.Entry(grp_target, font=("Consolas", 9))
        self.ent_hrd_p.pack(fill=tk.X, pady=(2, 4))

        ttk.Label(grp_target, text="Primitive Root (g):").pack(anchor=tk.W)
        self.ent_hrd_g = ttk.Entry(grp_target, font=("Consolas", 9))
        self.ent_hrd_g.pack(fill=tk.X, pady=(2, 4))

        ttk.Label(grp_target, text="Public Key Karyawan (y):").pack(anchor=tk.W)
        self.ent_hrd_y = ttk.Entry(grp_target, font=("Consolas", 9))
        self.ent_hrd_y.pack(fill=tk.X, pady=(2, 6))

        ttk.Button(grp_target, text="📥 Salin Public Key dari Portal Karyawan",
                   command=self._handle_copy_keys_to_hrd).pack(fill=tk.X)

        grp_enc = ttk.LabelFrame(right_col, text=" Proses Enkripsi ElGamal ", padding=10)
        grp_enc.pack(fill=tk.BOTH, expand=True)

        ttk.Button(grp_enc, text="🔒 Enkripsi Data Slip Gaji", style="Accent.TButton",
                   command=self._handle_elgamal_encrypt).pack(fill=tk.X, ipady=3, pady=(0, 6))

        ttk.Label(grp_enc, text="Ciphertext Blocks [(c1, c2), ...]:").pack(anchor=tk.W)
        self.txt_cipher_preview = tk.Text(grp_enc, height=7, font=("Consolas", 8), bg="#f8fafc", wrap=tk.CHAR)
        self.txt_cipher_preview.pack(fill=tk.BOTH, expand=True, pady=(2, 6))

        self.btn_export_enc = ttk.Button(grp_enc, text="📤 Simpan File .enc", state=tk.DISABLED,
                                         command=self._handle_export_enc_file)
        self.btn_export_enc.pack(fill=tk.X)

    # -------------------------------------------------------------------------
    # TAB 4: DLP MATH INSPECTOR (AUDIT TRAIL LOG)
    # -------------------------------------------------------------------------
    def _build_inspector_tab(self):
        container = ttk.Frame(self.tab_inspector)
        container.pack(fill=tk.BOTH, expand=True)

        ttk.Label(container, text="Audit Trail Langkah Perhitungan Diskrit:",
                  font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=(0, 6))

        self.txt_math_log = tk.Text(container, font=("Consolas", 9), bg="#0f172a", fg="#38bdf8", wrap=tk.WORD)
        scroll = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.txt_math_log.yview)
        self.txt_math_log.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.txt_math_log.pack(fill=tk.BOTH, expand=True)

        self._log_math("=== DLP MATH INSPECTOR ACTIVE ===")
        self._log_math("Semua jejak matematis modul Diffie-Hellman dan ElGamal dicatat di sini.\n")

    # =========================================================================
    # EVENT HANDLERS & BUSINESS LOGIC
    # =========================================================================

    def _log_math(self, text: str):
        self.txt_math_log.insert(tk.END, text + "\n")
        self.txt_math_log.see(tk.END)

    def _display_blank_payroll(self):
        self.txt_slip_output.delete("1.0", tk.END)
        self.txt_slip_output.insert(tk.END,
            "+-------------------------------------------------------------------+\n"
            "|               SLIP GAJI BELUM TERDEKRIPSI                         |\n"
            "|   Silakan muat file .enc dan masukkan Private Key x milik Anda    |\n"
            "+-------------------------------------------------------------------+\n"
        )

    # --- Handlers Diffie-Hellman ---
    def _handle_dh_generate_params(self):
        try:
            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] MEMBANGKITKAN PARAMETER PUBLIK DIFFIE-HELLMAN")
            self._log_math("="*70)

            # Bangkitkan safe prime 32-bit untuk kecepatan demo instan
            p, g = DLPEngine.generate_safe_prime_and_generator(bits=32)

            self.ent_dh_p.delete(0, tk.END)
            self.ent_dh_p.insert(0, str(p))
            self.ent_dh_g.delete(0, tk.END)
            self.ent_dh_g.insert(0, str(g))

            # Auto-generate private keys acak agar user bisa langsung klik handshake
            a = DiffieHellmanEngine.generate_private_key(p)
            b = DiffieHellmanEngine.generate_private_key(p)

            self.ent_dh_alice_priv.delete(0, tk.END)
            self.ent_dh_alice_priv.insert(0, str(a))
            self.ent_dh_bob_priv.delete(0, tk.END)
            self.ent_dh_bob_priv.insert(0, str(b))

            self._log_math(f"Modulus Prima Publik (p) : {p} ({p.bit_length()} bits)")
            self._log_math(f"Primitive Root / Basis (g): {g}")
            self._log_math(f"Private Key Alice acak (a): {a}")
            self._log_math(f"Private Key Bob acak (b)  : {b}")

            messagebox.showinfo("Sukses", "Domain parameters p dan g berhasil dibuat!")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def _handle_dh_execute_handshake(self):
        try:
            p = int(self.ent_dh_p.get().strip())
            g = int(self.ent_dh_g.get().strip())
            a = int(self.ent_dh_alice_priv.get().strip())
            b = int(self.ent_dh_bob_priv.get().strip())

            # 1. Hitung Public Key masing-masing pihak
            A = DiffieHellmanEngine.compute_public_key(g, a, p)
            B = DiffieHellmanEngine.compute_public_key(g, b, p)

            self.ent_dh_alice_pub.config(state="normal")
            self.ent_dh_alice_pub.delete(0, tk.END)
            self.ent_dh_alice_pub.insert(0, str(A))
            self.ent_dh_alice_pub.config(state="readonly")

            self.ent_dh_bob_pub.config(state="normal")
            self.ent_dh_bob_pub.delete(0, tk.END)
            self.ent_dh_bob_pub.insert(0, str(B))
            self.ent_dh_bob_pub.config(state="readonly")

            # 2. Pertukaran Public Key & Rekonstruksi Shared Secret
            K_A = DiffieHellmanEngine.compute_shared_secret(B, a, p)
            K_B = DiffieHellmanEngine.compute_shared_secret(A, b, p)

            self.ent_dh_alice_secret.config(state="normal")
            self.ent_dh_alice_secret.delete(0, tk.END)
            self.ent_dh_alice_secret.insert(0, str(K_A))
            self.ent_dh_alice_secret.config(state="readonly")

            self.ent_dh_bob_secret.config(state="normal")
            self.ent_dh_bob_secret.delete(0, tk.END)
            self.ent_dh_bob_secret.insert(0, str(K_B))
            self.ent_dh_bob_secret.config(state="readonly")

            # Log audit
            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] EKSEKUSI HANDSHAKE PROTOKOL DIFFIE-HELLMAN")
            self._log_math("="*70)
            self._log_math(f"1. Alice menghitung Public Key A = (g ^ a) mod p:")
            self._log_math(f"   A = ({g} ^ {a}) mod {p} = {A}")
            self._log_math(f"2. Bob menghitung Public Key B = (g ^ b) mod p:")
            self._log_math(f"   B = ({g} ^ {b}) mod {p} = {B}")
            self._log_math(f"3. Alice menerima B, menghitung K_A = (B ^ a) mod p:")
            self._log_math(f"   K_A = ({B} ^ {a}) mod {p} = {K_A}")
            self._log_math(f"4. Bob menerima A, menghitung K_B = (A ^ b) mod p:")
            self._log_math(f"   K_B = ({A} ^ {b}) mod {p} = {K_B}")

            if K_A == K_B:
                self.lbl_dh_status.config(text=f"Status: BERHASIL! Shared Secret Cocok ({K_A})", foreground="#059669")
                self._log_math(">> STATUS VERIFIKASI: K_A == K_B TERBUKTI IDENTIK SECARA MATEMATIS.")
                messagebox.showinfo("Handshake Berhasil", f"Shared Secret berhasil disepakati:\nK = {K_A}")
            else:
                self.lbl_dh_status.config(text="Status: GAGAL! Nilai kunci tidak cocok", foreground="#dc2626")
        except Exception as ex:
            messagebox.showerror("Error Handshake", str(ex))

    # --- Handlers ElGamal Portal Karyawan ---
    def _handle_elgamal_generate_keys(self):
        try:
            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] PEMBANGKITAN PASANGAN KUNCI ELGAMAL KARYAWAN")
            self._log_math("="*70)

            p, g, x, y = ElGamalEngine.generate_keypair(bits=40)
            self.elgamal_keys = {"p": p, "g": g, "x": x, "y": y}

            pub_str = f"p: {p}\ng: {g}\ny: {y}"
            priv_str = f"x: {x}"

            self.txt_elgamal_pub.delete("1.0", tk.END)
            self.txt_elgamal_pub.insert(tk.END, pub_str)

            self.txt_elgamal_priv.delete("1.0", tk.END)
            self.txt_elgamal_priv.insert(tk.END, priv_str)

            # Pre-fill input dekripsi
            self.ent_dec_p.delete(0, tk.END)
            self.ent_dec_p.insert(0, str(p))
            self.ent_dec_x.delete(0, tk.END)
            self.ent_dec_x.insert(0, str(x))

            self._log_math(f"1. Safe Prime Modulus (p) : {p} ({p.bit_length()} bits)")
            self._log_math(f"2. Generator / Primitive Root (g) : {g}")
            self._log_math(f"3. Private Key Karyawan (x)      : {x}")
            self._log_math(f"4. Menghitung Public Key y = (g ^ x) mod p:")
            self._log_math(f"   y = ({g} ^ {x}) mod {p} = {y}")
            self._log_math(">> Pasangan kunci ElGamal berhasil dikonstruksi secara valid.")

            messagebox.showinfo("Sukses", "Keypair ElGamal berhasil digenerate!\nPublic key siap diserahkan ke HRD.")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def _handle_save_elgamal_keys(self):
        if not self.elgamal_keys["p"]:
            messagebox.showwarning("Peringatan", "Bangkitkan kunci terlebih dahulu!")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            title="Simpan Keypair ElGamal"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(self.elgamal_keys, f, indent=4)
            messagebox.showinfo("Tersimpan", f"Kunci disimpan ke:\n{file_path}")

    def _handle_copy_keys_to_hrd(self):
        if not self.elgamal_keys["p"]:
            messagebox.showwarning("Peringatan", "Karyawan belum membangkitkan pasangan kunci!")
            return
        self.ent_hrd_p.delete(0, tk.END)
        self.ent_hrd_p.insert(0, str(self.elgamal_keys["p"]))
        self.ent_hrd_g.delete(0, tk.END)
        self.ent_hrd_g.insert(0, str(self.elgamal_keys["g"]))
        self.ent_hrd_y.delete(0, tk.END)
        self.ent_hrd_y.insert(0, str(self.elgamal_keys["y"]))
        messagebox.showinfo("Tersalin", "Public key Karyawan berhasil dimuat ke Portal HRD!")

    # --- Handlers HRD Enkripsi ---
    def _handle_elgamal_encrypt(self):
        try:
            p = int(self.ent_hrd_p.get().strip())
            g = int(self.ent_hrd_g.get().strip())
            y = int(self.ent_hrd_y.get().strip())

            gaji_pokok = float(self.hrd_entries["gaji_pokok"].get().strip())
            tunjangan = float(self.hrd_entries["tunjangan"].get().strip())
            potongan_bpjs = float(self.hrd_entries["potongan_bpjs"].get().strip())
            potongan_pph = float(self.hrd_entries["potongan_pph"].get().strip())
            take_home_pay = (gaji_pokok + tunjangan) - (potongan_bpjs + potongan_pph)

            payload_dict = {
                "nik": self.hrd_entries["nik"].get().strip(),
                "nama": self.hrd_entries["nama"].get().strip(),
                "jabatan": self.hrd_entries["jabatan"].get().strip(),
                "periode": self.hrd_entries["periode"].get().strip(),
                "rincian": {
                    "gaji_pokok": gaji_pokok,
                    "tunjangan": tunjangan,
                    "potongan_bpjs": potongan_bpjs,
                    "potongan_pph": potongan_pph,
                    "take_home_pay": take_home_pay
                },
                "catatan": self.hrd_entries["catatan"].get().strip(),
                "timestamp": datetime.now().isoformat()
            }

            raw_bytes = json.dumps(payload_dict, ensure_ascii=False).encode("utf-8")

            # Eksekusi Enkripsi ElGamal
            cipher_pairs, block_size, metadata = ElGamalEngine.encrypt_bytes(raw_bytes, p, g, y)

            self.generated_enc_payload = {
                "target_nik": payload_dict["nik"],
                "algorithm": "Manual-ElGamal-DLP",
                "domain_p": p,
                "block_byte_size": block_size,
                "block_lengths": [m["byte_len"] for m in metadata],
                "ciphertext": cipher_pairs
            }

            preview_str = ",\n".join([f"({c1}, {c2})" for c1, c2 in cipher_pairs])
            self.txt_cipher_preview.delete("1.0", tk.END)
            self.txt_cipher_preview.insert(tk.END, preview_str)
            self.btn_export_enc.config(state=tk.NORMAL)

            # Audit Log
            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] PROSES ENKRIPSI SLIP GAJI ELGAMAL DI HRD")
            self._log_math("="*70)
            self._log_math(f"Panjang Payload Asli: {len(raw_bytes)} bytes")
            self._log_math(f"Ukuran Blok Maksimal: {block_size} bytes (agar integer m < p)")
            self._log_math(f"Jumlah Pasangan Ciphertext Dihasilkan: {len(cipher_pairs)} blok")
            self._log_math("Contoh Perhitungan 2 Blok Pertama:")
            for sample in metadata[:2]:
                idx = sample['index']
                self._log_math(f"  * Blok #{idx}:")
                self._log_math(f"    - Plaintext Integer m_{idx} = {sample['m_int']}")
                self._log_math(f"    - Ephemeral Key k_{idx}     = {sample['k_nonce']}")
                self._log_math(f"    - c1 = (g ^ k) mod p       = ({g} ^ {sample['k_nonce']}) mod {p} = {sample['c1']}")
                self._log_math(f"    - c2 = (m * y^k) mod p     = {sample['c2']}")

            messagebox.showinfo("Sukses", f"Data berhasil dienkripsi ke dalam {len(cipher_pairs)} blok pasangan ElGamal.")
        except Exception as ex:
            messagebox.showerror("Error Enkripsi", str(ex))

    def _handle_export_enc_file(self):
        if not hasattr(self, 'generated_enc_payload'):
            return

        default_fname = f"slip_gaji_{self.generated_enc_payload['target_nik']}.enc"
        file_path = filedialog.asksaveasfilename(
            initialfile=default_fname,
            defaultextension=".enc",
            filetypes=[("Encrypted File", "*.enc"), ("JSON File", "*.json")],
            title="Ekspor Berkas Slip Gaji Terenkripsi"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(self.generated_enc_payload, f, indent=2)
            messagebox.showinfo("Berhasil", f"Berkas terenkripsi disimpan ke:\n{file_path}")

    # --- Handlers Karyawan Dekripsi ---
    def _handle_load_enc_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Encrypted File", "*.enc"), ("JSON File", "*.json"), ("All Files", "*.*")],
            title="Pilih Berkas Slip Gaji Terenkripsi"
        )
        if file_path:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "ciphertext" not in data or "block_lengths" not in data:
                    raise ValueError("Format file .enc tidak dikenali!")

                self.loaded_enc_payload = data
                fname = os.path.basename(file_path)
                self.lbl_enc_info.config(
                    text=f"Berkas: {fname} (Target: {data.get('target_nik', '-')}, {len(data['ciphertext'])} blok)",
                    foreground="#059669"
                )
                if "domain_p" in data:
                    self.ent_dec_p.delete(0, tk.END)
                    self.ent_dec_p.insert(0, str(data["domain_p"]))

                messagebox.showinfo("File Dimuat", f"Berkas {fname} berhasil dimuat.")
            except Exception as ex:
                messagebox.showerror("Gagal Membaca File", str(ex))

    def _handle_elgamal_decrypt(self):
        try:
            if not self.loaded_enc_payload:
                messagebox.showwarning("Peringatan", "Muat file .enc terlebih dahulu!")
                return

            p = int(self.ent_dec_p.get().strip())
            x = int(self.ent_dec_x.get().strip())

            cipher_pairs = self.loaded_enc_payload["ciphertext"]
            block_lengths = self.loaded_enc_payload["block_lengths"]

            # Dekripsi ElGamal
            decrypted_bytes, trace = ElGamalEngine.decrypt_bytes(cipher_pairs, block_lengths, p, x)

            payroll_dict = json.loads(decrypted_bytes.decode("utf-8"))
            self._render_payroll_card(payroll_dict)

            # Audit Log
            self._log_math("\n" + "="*70)
            self._log_math(f"[{datetime.now().strftime('%H:%M:%S')}] PROSES DEKRIPSI SLIP GAJI DI SISI KARYAWAN")
            self._log_math("="*70)
            self._log_math(f"Jumlah Pasangan Blok Didekripsi: {len(cipher_pairs)}")
            self._log_math("Contoh Perhitungan Dekripsi 2 Blok Pertama:")
            for sample in trace[:2]:
                idx = sample['index']
                self._log_math(f"  * Blok #{idx}:")
                self._log_math(f"    - c1 = {sample['c1']}, c2 = {sample['c2']}")
                self._log_math(f"    - Shared Secret S = (c1 ^ x) mod p = {sample['recovered_s']}")
                self._log_math(f"    - Modular Inverse S^(-1) mod p    = {sample['s_inv']}")
                self._log_math(f"    - Plaintext m = (c2 * S^(-1)) mod p = {sample['m_int']}")

            messagebox.showinfo("Berhasil", "Dekripsi berhasil! Slip gaji telah diverifikasi secara sah.")
        except json.JSONDecodeError:
            messagebox.showerror("Dekripsi Gagal", "Private Key salah! Hasil dekripsi bukan format data yang valid.")
        except Exception as ex:
            messagebox.showerror("Error Dekripsi", str(ex))

    def _render_payroll_card(self, data: dict):
        rincian = data["rincian"]
        card = (
            "=====================================================================\n"
            "                 PT. TEKNOLOGI INFORMASI NUSANTARA                   \n"
            "                     SLIP GAJI RESMI KARYAWAN                        \n"
            "         STATUS KEAMANAN: RAHASIA (DEKRIPSI ELGAMAL VALID)           \n"
            "=====================================================================\n"
            f" NIK              : {data.get('nik')}\n"
            f" Nama Karyawan    : {data.get('nama')}\n"
            f" Jabatan / Divisi : {data.get('jabatan')}\n"
            f" Periode Gaji     : {data.get('periode')}\n"
            f" Tanggal Terbit   : {data.get('timestamp')}\n"
            "---------------------------------------------------------------------\n"
            " RINCIAN PENDAPATAN (EARNINGS):\n"
            f"  + Gaji Pokok                         : Rp {rincian['gaji_pokok']:>14,.2f}\n"
            f"  + Tunjangan Jabatan & Operasional    : Rp {rincian['tunjangan']:>14,.2f}\n"
            f"  TOTAL PENDAPATAN KOTOR (GROSS)       : Rp {(rincian['gaji_pokok'] + rincian['tunjangan']):>14,.2f}\n"
            "---------------------------------------------------------------------\n"
            " RINCIAN PEMOTONGAN (DEDUCTIONS):\n"
            f"  - Iuran Jaminan Sosial (BPJS)        : Rp {rincian['potongan_bpjs']:>14,.2f}\n"
            f"  - Pajak Penghasilan (PPh 21)         : Rp {rincian['potongan_pph']:>14,.2f}\n"
            f"  TOTAL POTONGAN                       : Rp {(rincian['potongan_bpjs'] + rincian['potongan_pph']):>14,.2f}\n"
            "=====================================================================\n"
            f" GAJI BERSIH DITERIMA (TAKE HOME PAY)  : Rp {rincian['take_home_pay']:>14,.2f}\n"
            "=====================================================================\n"
            f" Catatan HRD:\n \"{data.get('catatan')}\"\n"
            "---------------------------------------------------------------------\n"
            " Berkas berhasil didekripsi menggunakan Private Key x ElGamal milik karyawan.\n"
            "=====================================================================\n"
        )
        self.txt_slip_output.delete("1.0", tk.END)
        self.txt_slip_output.insert(tk.END, card)


# =============================================================================
# ENTRY POINT UTAMA
# =============================================================================
if __name__ == "__main__":
    app = CryptographyApp()
    app.mainloop()