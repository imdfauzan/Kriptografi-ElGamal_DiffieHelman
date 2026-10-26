import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import random
import json


# ==============================================================================
# SECTION 1: CORE MATH LOGIC (MESIN MATEMATIKA DASAR TANPA LIBRARY)
# ==============================================================================

def mod_exp(base, exp, mod):
    """Square-and-Multiply: Menghitung (base^exp) mod p secara efisien."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp // 2
        base = (base * base) % mod
    return result


def is_prime(n):
    """Mengecek apakah n adalah bilangan prima dengan uji pembagian hingga akar n."""
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def generate_prime(min_val=2000, max_val=9999):
    """Membangkitkan bilangan prima acak pada rentang tertentu."""
    while True:
        candidate = random.randint(min_val, max_val)
        if is_prime(candidate):
            return candidate


def get_prime_factors(n):
    """Mencari seluruh faktor prima unik dari n (digunakan untuk mencari primitive root)."""
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return sorted(list(factors))


def find_primitive_root(p):
    """
    Mencari primitive root (generator g) dari bilangan prima p.
    Syarat: untuk setiap faktor prima q dari (p-1), harus berlaku g^((p-1)/q) mod p != 1.
    """
    phi = p - 1
    factors = get_prime_factors(phi)
    for g in range(2, p):
        is_primitive = True
        for q in factors:
            if mod_exp(g, phi // q, p) == 1:
                is_primitive = False
                break
        if is_primitive:
            return g, factors
    return None, []


def extended_gcd(a, b):
    """Extended Euclidean Algorithm: Mengembalikan (gcd, x, y) sehingga a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a, p):
    """Mencari modular multiplicative inverse dari a modulo p: (a * a_inv) mod p == 1."""
    gcd, x, _ = extended_gcd(a % p, p)
    if gcd != 1:
        raise ValueError("Modular inverse tidak ditemukan.")
    return (x % p + p) % p


# ==============================================================================
# SECTION 2: DIFFIE-HELLMAN & ELGAMAL CRYPTO LOGIC (ALGORITMA KRIPTOGRAFI)
# ==============================================================================

def dh_generate_keypair(p, g):
    """
    Membangkitkan pasangan kunci Diffie-Hellman / ElGamal:
    - private_key (x atau y): bilangan bulat acak rahasia di rentang [2, p-2]
    - public_key (X atau Y) : g^private_key mod p
    """
    private_key = random.randint(2, p - 2)
    public_key = mod_exp(g, private_key, p)
    return private_key, public_key


def dh_compute_shared_key(other_public_key, my_private_key, p):
    """
    Menghitung Shared Secret Key Diffie-Hellman:
    K = (Public_Lawan ^ Private_Sendiri) mod p
    """
    return mod_exp(other_public_key, my_private_key, p)


def elgamal_encrypt(plaintext, p, g, y_pub):
    """
    Mengenkripsi teks menggunakan algoritma ElGamal:
    Setiap karakter diubah ke ASCII (m), lalu dikunci dengan ephemeral key acak (k):
    - a = g^k mod p
    - b = (y^k * m) mod p
    """
    ciphertext_pairs = []
    logs = []

    for idx, char in enumerate(plaintext):
        m = ord(char)
        k = random.randint(2, p - 2)

        a = mod_exp(g, k, p)
        shared_mask = mod_exp(y_pub, k, p)
        b = (shared_mask * m) % p

        ciphertext_pairs.append([a, b])

        if idx < 5:
            logs.append(
                f"  Blok[{idx}] '{char}' (ASCII m={m}) | Random k={k}\n"
                f"    -> a = {g}^{k} mod {p} = {a}\n"
                f"    -> y^k = {y_pub}^{k} mod {p} = {shared_mask}\n"
                f"    -> b = ({shared_mask} * {m}) mod {p} = {b}\n"
                f"    -> Ciphertext (a, b) = ({a}, {b})"
            )

    return ciphertext_pairs, logs


def elgamal_decrypt(ciphertext_pairs, p, x_priv):
    """
    Mendekripsi pasangan ciphertext (a, b) menggunakan Private Key Karyawan (x):
    - Hitung shared mask s = a^x mod p
    - Cari invers s_inv = s^(-1) mod p (setara dengan a^(p-1-x) mod p)
    - Pulihkan m = (b * s_inv) mod p
    """
    decrypted_chars = []
    logs = []

    for idx, pair in enumerate(ciphertext_pairs):
        a, b = pair[0], pair[1]

        s = mod_exp(a, x_priv, p)
        s_inv = mod_inverse(s, p)
        s_inv_fermat = mod_exp(a, p - 1 - x_priv, p)

        m = (b * s_inv) % p
        char = chr(m)
        decrypted_chars.append(char)

        if idx < 5:
            logs.append(
                f"  Blok[{idx}] Ciphertext (a={a}, b={b})\n"
                f"    -> Shared Mask s = a^x mod p = {a}^{x_priv} mod {p} = {s}\n"
                f"    -> Modular Inverse s^(-1) mod {p} = {s_inv} (Uji Fermat a^(p-1-x) = {s_inv_fermat})\n"
                f"    -> Plaintext m = (b * s^(-1)) mod p = ({b} * {s_inv}) mod {p} = {m} ('{char}')"
            )

    return "".join(decrypted_chars), logs


# ==============================================================================
# SECTION 3: GUI & APPLICATION FLOW (ANTARMUKA TKINTER 3 TAB)
# ==============================================================================

class CryptoPayrollApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Sistem Distribusi Slip Gaji Terenkripsi - Diffie-Hellman & ElGamal")
        self.root.geometry("920x680")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_karyawan = ttk.Frame(self.notebook)
        self.tab_hrd = ttk.Frame(self.notebook)
        self.tab_log = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_karyawan, text="Tab 1: Karyawan")
        self.notebook.add(self.tab_hrd, text="Tab 2: HRD")
        self.notebook.add(self.tab_log, text="Tab 3: Log Perhitungan")

        self.setup_tab_karyawan()
        self.setup_tab_hrd()
        self.setup_tab_log()

    # --------------------------------------------------------------------------
    # UI SETUP: TAB 1 (KARYAWAN)
    # --------------------------------------------------------------------------
    def setup_tab_karyawan(self):
        frame_keygen = ttk.LabelFrame(
            self.tab_karyawan,
            text="1. Pembangkitan Parameter Publik (p, g) & Kunci Karyawan",
            padding=10
        )
        frame_keygen.pack(fill="x", padx=10, pady=8)

        btn_gen = ttk.Button(
            frame_keygen,
            text="Generate Parameter & Kunci Karyawan (Kirim Public Key ke Tab HRD)",
            command=self.action_generate_keys
        )
        btn_gen.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 8))

        ttk.Label(frame_keygen, text="Bilangan Prima (p):").grid(row=1, column=0, sticky="w", padx=5, pady=3)
        self.ent_kar_p = ttk.Entry(frame_keygen, width=18)
        self.ent_kar_p.grid(row=1, column=1, sticky="w", padx=5, pady=3)

        ttk.Label(frame_keygen, text="Primitive Root (g):").grid(row=1, column=2, sticky="w", padx=5, pady=3)
        self.ent_kar_g = ttk.Entry(frame_keygen, width=18)
        self.ent_kar_g.grid(row=1, column=3, sticky="w", padx=5, pady=3)

        ttk.Label(frame_keygen, text="Private Key Karyawan (x) [RAHASIA]:").grid(row=2, column=0, sticky="w", padx=5, pady=3)
        self.ent_kar_x = ttk.Entry(frame_keygen, width=18)
        self.ent_kar_x.grid(row=2, column=1, sticky="w", padx=5, pady=3)

        ttk.Label(frame_keygen, text="Public Key Karyawan (Y = g^x mod p):").grid(row=2, column=2, sticky="w", padx=5, pady=3)
        self.ent_kar_Y = ttk.Entry(frame_keygen, width=18)
        self.ent_kar_Y.grid(row=2, column=3, sticky="w", padx=5, pady=3)

        frame_dh_kar = ttk.LabelFrame(
            self.tab_karyawan,
            text="2. Verifikasi Pertukaran Kunci Diffie-Hellman (Sisi Karyawan)",
            padding=10
        )
        frame_dh_kar.pack(fill="x", padx=10, pady=5)

        ttk.Label(frame_dh_kar, text="Public Value dari HRD (X):").grid(row=0, column=0, sticky="w", padx=5)
        self.ent_kar_hrd_X = ttk.Entry(frame_dh_kar, width=18)
        self.ent_kar_hrd_X.grid(row=0, column=1, sticky="w", padx=5)

        ttk.Label(frame_dh_kar, text="Shared Secret Key (K' = X^x mod p):").grid(row=0, column=2, sticky="w", padx=5)
        self.ent_kar_shared_K = ttk.Entry(frame_dh_kar, width=18)
        self.ent_kar_shared_K.grid(row=0, column=3, sticky="w", padx=5)

        frame_dec = ttk.LabelFrame(
            self.tab_karyawan,
            text="3. Dekripsi File Slip Gaji (.enc) dengan ElGamal",
            padding=10
        )
        frame_dec.pack(fill="both", expand=True, padx=10, pady=8)

        btn_load_dec = ttk.Button(
            frame_dec,
            text="Load File Slip Gaji (.enc) & Dekripsi Sekarang",
            command=self.action_load_and_decrypt
        )
        btn_load_dec.pack(fill="x", pady=(0, 8))

        self.txt_decrypted_slip = tk.Text(frame_dec, height=14, font=("Consolas", 10))
        self.txt_decrypted_slip.pack(fill="both", expand=True)

    # --------------------------------------------------------------------------
    # UI SETUP: TAB 2 (HRD)
    # --------------------------------------------------------------------------
    def setup_tab_hrd(self):
        frame_pub = ttk.LabelFrame(
            self.tab_hrd,
            text="1. Parameter Publik Karyawan & Simulasi Diffie-Hellman Handshake",
            padding=10
        )
        frame_pub.pack(fill="x", padx=10, pady=8)

        ttk.Label(frame_pub, text="Prima (p):").grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.ent_hrd_p = ttk.Entry(frame_pub, width=14)
        self.ent_hrd_p.grid(row=0, column=1, sticky="w", padx=5, pady=3)

        ttk.Label(frame_pub, text="Generator (g):").grid(row=0, column=2, sticky="w", padx=5, pady=3)
        self.ent_hrd_g = ttk.Entry(frame_pub, width=14)
        self.ent_hrd_g.grid(row=0, column=3, sticky="w", padx=5, pady=3)

        ttk.Label(frame_pub, text="Public Key Karyawan (Y):").grid(row=0, column=4, sticky="w", padx=5, pady=3)
        self.ent_hrd_Y = ttk.Entry(frame_pub, width=14)
        self.ent_hrd_Y.grid(row=0, column=5, sticky="w", padx=5, pady=3)

        btn_dh = ttk.Button(
            frame_pub,
            text="Uji Pertukaran Kunci Diffie-Hellman (Hitung Shared Secret K antara HRD & Karyawan)",
            command=self.action_diffie_hellman_handshake
        )
        btn_dh.grid(row=1, column=0, columnspan=6, sticky="ew", pady=8)

        ttk.Label(frame_pub, text="Private HRD (y):").grid(row=2, column=0, sticky="w", padx=5)
        self.ent_hrd_y = ttk.Entry(frame_pub, width=14)
        self.ent_hrd_y.grid(row=2, column=1, sticky="w", padx=5)

        ttk.Label(frame_pub, text="Public HRD (X = g^y mod p):").grid(row=2, column=2, sticky="w", padx=5)
        self.ent_hrd_X = ttk.Entry(frame_pub, width=14)
        self.ent_hrd_X.grid(row=2, column=3, sticky="w", padx=5)

        ttk.Label(frame_pub, text="Shared Key (K = Y^y mod p):").grid(row=2, column=4, sticky="w", padx=5)
        self.ent_hrd_shared_K = ttk.Entry(frame_pub, width=14)
        self.ent_hrd_shared_K.grid(row=2, column=5, sticky="w", padx=5)

        frame_form = ttk.LabelFrame(
            self.tab_hrd,
            text="2. Input Rincian Gaji Karyawan & Enkripsi ElGamal",
            padding=10
        )
        frame_form.pack(fill="both", expand=True, padx=10, pady=8)

        labels = [
            ("Nama Karyawan:", "Budi Santoso"),
            ("NIP / Jabatan:", "19980422 - System Engineer"),
            ("Periode Gaji:", "Oktober 2026"),
            ("Gaji Pokok (Rp):", "12.500.000"),
            ("Tunjangan Kinerja (Rp):", "3.250.000"),
            ("Potongan Pajak/BPJS (Rp):", "750.000"),
            ("Total Take Home Pay (Rp):", "15.000.000")
        ]
        self.hrd_entries = []
        for i, (lbl_text, default_val) in enumerate(labels):
            ttk.Label(frame_form, text=lbl_text).grid(row=i, column=0, sticky="w", padx=5, pady=4)
            ent = ttk.Entry(frame_form, width=45)
            ent.insert(0, default_val)
            ent.grid(row=i, column=1, sticky="w", padx=5, pady=4)
            self.hrd_entries.append((lbl_text, ent))

        btn_enc = ttk.Button(
            frame_form,
            text="Enkripsi Slip Gaji dengan ElGamal & Simpan ke File (.enc)",
            command=self.action_encrypt_and_save
        )
        btn_enc.grid(row=len(labels), column=0, columnspan=2, sticky="ew", pady=12)

    # --------------------------------------------------------------------------
    # UI SETUP: TAB 3 (LOG PERHITUNGAN)
    # --------------------------------------------------------------------------
    def setup_tab_log(self):
        top_bar = ttk.Frame(self.tab_log)
        top_bar.pack(fill="x", padx=10, pady=5)

        ttk.Label(
            top_bar,
            text="Catatan Alur Perhitungan Matematika (Diffie-Hellman & ElGamal Step-by-Step):"
        ).pack(side="left")

        ttk.Button(top_bar, text="Bersihkan Log", command=self.clear_log).pack(side="right")

        self.txt_log = tk.Text(self.tab_log, font=("Consolas", 10))
        self.txt_log.pack(fill="both", expand=True, padx=10, pady=5)

    def write_log(self, text):
        self.txt_log.insert(tk.END, text + "\n")
        self.txt_log.see(tk.END)

    def clear_log(self):
        self.txt_log.delete("1.0", tk.END)

    # --------------------------------------------------------------------------
    # EVENT HANDLERS (ALUR EKSEKUSI TOMBOL)
    # --------------------------------------------------------------------------
    def action_generate_keys(self):
        p = generate_prime(2000, 9999)
        g, factors = find_primitive_root(p)
        x_priv, Y_pub = dh_generate_keypair(p, g)

        for ent, val in [
            (self.ent_kar_p, p), (self.ent_kar_g, g),
            (self.ent_kar_x, x_priv), (self.ent_kar_Y, Y_pub),
            (self.ent_hrd_p, p), (self.ent_hrd_g, g), (self.ent_hrd_Y, Y_pub)
        ]:
            ent.delete(0, tk.END)
            ent.insert(0, str(val))

        self.write_log("=" * 78)
        self.write_log("[TAHAP 1] PEMBANGKITAN PARAMETER PUBLIK & KUNCI KARYAWAN")
        self.write_log("=" * 78)
        self.write_log(f"1. Bilangan Prima (p) terpilih       : {p}")
        self.write_log(f"2. Faktor prima dari (p-1 = {p-1})    : {factors}")
        self.write_log(f"3. Primitive Root (g) terkecil       : {g}")
        self.write_log(f"4. Private Key Karyawan (x) [RAHASIA]: {x_priv}")
        self.write_log(f"5. Public Key Karyawan (Y)           : g^x mod p = {g}^{x_priv} mod {p} = {Y_pub}")
        self.write_log("-> Public Key (p, g, Y) berhasil didistribusikan ke Tab 2: HRD.\n")

        messagebox.showinfo(
            "Key Generation Berhasil",
            f"Parameter Publik (p={p}, g={g}) dan Public Key Karyawan (Y={Y_pub}) "
            f"telah dibuat dan dikirim otomatis ke Tab 2: HRD."
        )

    def action_diffie_hellman_handshake(self):
        try:
            p = int(self.ent_hrd_p.get())
            g = int(self.ent_hrd_g.get())
            Y_kar = int(self.ent_hrd_Y.get())
            x_kar = int(self.ent_kar_x.get())
        except ValueError:
            messagebox.showwarning("Peringatan", "Silakan klik Generate Kunci di Tab 1: Karyawan terlebih dahulu!")
            return

        y_hrd, X_hrd = dh_generate_keypair(p, g)
        K_hrd = dh_compute_shared_key(Y_kar, y_hrd, p)
        K_kar = dh_compute_shared_key(X_hrd, x_kar, p)

        for ent, val in [
            (self.ent_hrd_y, y_hrd), (self.ent_hrd_X, X_hrd), (self.ent_hrd_shared_K, K_hrd),
            (self.ent_kar_hrd_X, X_hrd), (self.ent_kar_shared_K, K_kar)
        ]:
            ent.delete(0, tk.END)
            ent.insert(0, str(val))

        self.write_log("=" * 78)
        self.write_log("[TAHAP 2] PERTUKARAN KUNCI DIFFIE-HELLMAN (KEY EXCHANGE HANDSHAKE)")
        self.write_log("=" * 78)
        self.write_log(f"Parameter Publik Disepakati : p = {p}, g = {g}")
        self.write_log(f"Sisi Karyawan               : Private x = {x_kar} | Public Y = {g}^{x_kar} mod {p} = {Y_kar}")
        self.write_log(f"Sisi HRD                    : Private y = {y_hrd} | Public X = {g}^{y_hrd} mod {p} = {X_hrd}")
        self.write_log("-" * 78)
        self.write_log(f"Perhitungan Shared Key HRD      (K  = Y^y mod p) : {Y_kar}^{y_hrd} mod {p} = {K_hrd}")
        self.write_log(f"Perhitungan Shared Key Karyawan (K' = X^x mod p) : {X_hrd}^{x_kar} mod {p} = {K_kar}")
        self.write_log(f"Status Kesepakatan Kunci        : {'COCOK / VALID (K == K\')' if K_hrd == K_kar else 'GAGAL'}\n")

        messagebox.showinfo(
            "Diffie-Hellman Handshake Sukses",
            f"Shared Secret Key berhasil disepakati!\n\n"
            f"Di sisi HRD (K) = {K_hrd}\n"
            f"Di sisi Karyawan (K') = {K_kar}\n\n"
            f"Detail perhitungan dapat dilihat pada Tab 3: Log Perhitungan."
        )

    def action_encrypt_and_save(self):
        try:
            p = int(self.ent_hrd_p.get())
            g = int(self.ent_hrd_g.get())
            Y_pub = int(self.ent_hrd_Y.get())
        except ValueError:
            messagebox.showwarning("Peringatan", "Parameter Publik (p, g, Y) belum terisi!")
            return

        lines = ["=== SLIP GAJI KARYAWAN RAHASIA ==="]
        for lbl, ent in self.hrd_entries:
            lines.append(f"{lbl:<26} {ent.get()}")
        plaintext = "\n".join(lines)

        ciphertext_pairs, sample_logs = elgamal_encrypt(plaintext, p, g, Y_pub)

        file_path = filedialog.asksaveasfilename(
            defaultextension=".enc",
            filetypes=[("Encrypted Slip File", "*.enc")],
            initialfile="slip_gaji_elgamal.enc",
            title="Simpan File Slip Gaji Terenkripsi (.enc)"
        )
        if not file_path:
            return

        payload = {
            "algorithm": "ElGamal & Diffie-Hellman",
            "public_p": p,
            "public_g": g,
            "public_Y": Y_pub,
            "ciphertext": ciphertext_pairs
        }
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        self.write_log("=" * 78)
        self.write_log("[TAHAP 3] ENKRIPSI SLIP GAJI DENGAN ALGORITMA ELGAMAL (OLEH HRD)")
        self.write_log("=" * 78)
        self.write_log(f"Menggunakan Public Key Karyawan : (p={p}, g={g}, Y={Y_pub})")
        self.write_log(f"Panjang Karakter Plaintext      : {len(plaintext)} karakter")
        self.write_log("Sampel Perhitungan Enkripsi 5 Karakter Pertama:")
        for log_line in sample_logs:
            self.write_log(log_line)
        self.write_log(f"-> Total {len(ciphertext_pairs)} pasang blok (a, b) disimpan ke: {file_path}\n")

        messagebox.showinfo(
            "Enkripsi ElGamal Selesai",
            f"Slip gaji berhasil dienkripsi menjadi {len(ciphertext_pairs)} pasang blok (a, b) "
            f"dan disimpan ke:\n{file_path}"
        )

    def action_load_and_decrypt(self):
        try:
            x_priv = int(self.ent_kar_x.get())
        except ValueError:
            messagebox.showwarning("Peringatan", "Private Key Karyawan (x) belum tersedia!")
            return

        file_path = filedialog.askopenfilename(
            filetypes=[("Encrypted Slip File", "*.enc")],
            title="Pilih File Slip Gaji Terenkripsi (.enc)"
        )
        if not file_path:
            return

        with open(file_path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        p = int(payload["public_p"])
        ciphertext_pairs = payload["ciphertext"]

        decrypted_text, sample_logs = elgamal_decrypt(ciphertext_pairs, p, x_priv)

        self.txt_decrypted_slip.delete("1.0", tk.END)
        self.txt_decrypted_slip.insert(tk.END, decrypted_text)

        self.write_log("=" * 78)
        self.write_log("[TAHAP 4] DEKRIPSI SLIP GAJI DENGAN ALGORITMA ELGAMAL (OLEH KARYAWAN)")
        self.write_log("=" * 78)
        self.write_log(f"File Sumber                : {file_path}")
        self.write_log(f"Menggunakan Private Key (x): {x_priv} dan Prima (p): {p}")
        self.write_log("Sampel Perhitungan Dekripsi 5 Karakter Pertama:")
        for log_line in sample_logs:
            self.write_log(log_line)
        self.write_log("-> Seluruh blok berhasil didekripsi kembali menjadi teks slip gaji asli.\n")

        messagebox.showinfo("Dekripsi Berhasil", "Slip gaji (.enc) berhasil didekripsi! Silakan cek hasilnya.")


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoPayrollApp(root)
    root.mainloop()