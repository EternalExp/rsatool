# rsa_tool.py
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

# ---------------------------
#  多语言文本（中文 / English）
# ---------------------------
TEXTS = {
    "title": {"zh": "RSA 本地工具", "en": "RSA Local Tool"},
    "lang_label": {"zh": "语言：", "en": "Language:"},
    "tab_generate": {"zh": "生成密钥", "en": "Generate Keys"},
    "tab_encrypt": {"zh": "公钥加密", "en": "Encrypt (Public Key)"},
    "tab_decrypt": {"zh": "私钥解密", "en": "Decrypt (Private Key)"},
    "keysize_label": {"zh": "密钥位数：", "en": "Key size:"},
    "generate_btn": {"zh": "生成", "en": "Generate"},
    "copy_pub": {"zh": "复制公钥", "en": "Copy Public Key"},
    "copy_priv": {"zh": "复制私钥", "en": "Copy Private Key"},
    "pubkey_label": {"zh": "公钥 (PEM)：", "en": "Public Key (PEM):"},
    "privkey_label": {"zh": "私钥 (PEM)：", "en": "Private Key (PEM):"},
    "plaintext_label": {"zh": "明文：", "en": "Plaintext:"},
    "ciphertext_label": {"zh": "密文 (Base64)：", "en": "Ciphertext (Base64):"},
    "encrypt_btn": {"zh": "加密", "en": "Encrypt"},
    "decrypt_btn": {"zh": "解密", "en": "Decrypt"},
    "copy_out": {"zh": "复制输出", "en": "Copy Output"},
    "status_ready": {"zh": "就绪", "en": "Ready"},
    "status_generating": {"zh": "生成中，请稍候…", "en": "Generating, please wait..."},
    "err_invalid_key": {"zh": "无效的密钥或格式。请检查 PEM 文本。", "en": "Invalid key or format. Please check the PEM text."},
    "err_decrypt": {"zh": "解密失败（可能密钥或密文错误）。", "en": "Decryption failed (possible wrong key or ciphertext)."},
    "err_encrypt": {"zh": "加密失败（可能公钥格式错误或消息太大）。", "en": "Encryption failed (possible invalid public key or message)."},
    "ok_generated": {"zh": "密钥生成成功。", "en": "Keypair generated."},
}

# ---------------------------
#  辅助：语言取值
# ---------------------------
def t(key, lang):
    return TEXTS.get(key, {}).get(lang, "")

# ---------------------------
#  RSA 分块加解密（OAEP）
# ---------------------------
def rsa_encrypt_pem(pub_pem: str, data: bytes) -> bytes:
    key = RSA.import_key(pub_pem)
    cipher = PKCS1_OAEP.new(key)
    key_bytes = (key.size_in_bits() + 7) // 8
    hash_size = SHA1.digest_size
    max_chunk = key_bytes - 2 * hash_size - 2
    if max_chunk <= 0:
        raise ValueError("Key too small or invalid for OAEP.")
    out = bytearray()
    for i in range(0, len(data), max_chunk):
        chunk = data[i:i + max_chunk]
        enc = cipher.encrypt(chunk)
        out.extend(enc)
    return bytes(out)

def rsa_decrypt_pem(priv_pem: str, cipherdata: bytes) -> bytes:
    key = RSA.import_key(priv_pem)
    cipher = PKCS1_OAEP.new(key)
    key_bytes = (key.size_in_bits() + 7) // 8
    if len(cipherdata) % key_bytes != 0:
        raise ValueError("Ciphertext length not a multiple of RSA block size.")
    out = bytearray()
    for i in range(0, len(cipherdata), key_bytes):
        block = cipherdata[i:i + key_bytes]
        dec = cipher.decrypt(block)
        out.extend(dec)
    return bytes(out)

# ---------------------------
#  GUI 主类
# ---------------------------
class RSAToolApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.lang = "zh"  # 'zh' 或 'en'
        self.title(t("title", self.lang))
        self.geometry("920x640")
        self.resizable(True, True)

        self._build_ui()
        self._set_status(t("status_ready", self.lang))

        # 最新生成的密钥（内存中）
        self.last_public_pem = None
        self.last_private_pem = None

    def _build_ui(self):
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=8, pady=6)

        ttk.Label(top_frame, text=t("lang_label", self.lang)).pack(side="left")
        self.lang_box = ttk.Combobox(top_frame, values=["中文", "English"], width=8, state="readonly")
        self.lang_box.current(0 if self.lang == "zh" else 1)
        self.lang_box.bind("<<ComboboxSelected>>", self._on_lang_change)
        self.lang_box.pack(side="left", padx=(2, 10))

        self.status_var = tk.StringVar(value="")
        self.status_label = ttk.Label(top_frame, textvariable=self.status_var)
        self.status_label.pack(side="right")

        # Notebook（3 页）
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=6)

        self._build_tab_generate()
        self._build_tab_encrypt()
        self._build_tab_decrypt()

    # ---------------------------
    #  页：生成密钥
    # ---------------------------
    def _build_tab_generate(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=t("tab_generate", self.lang))

        top = ttk.Frame(frame)
        top.pack(fill="x", padx=8, pady=6)

        ttk.Label(top, text=t("keysize_label", self.lang)).pack(side="left")
        self.keysize_box = ttk.Combobox(top, values=["512", "1024", "2048", "4096"], width=8, state="readonly")
        self.keysize_box.current(1)  # 默认 1024
        self.keysize_box.pack(side="left", padx=(2,10))

        self.gen_btn = ttk.Button(top, text=t("generate_btn", self.lang), command=self._generate_keys_thread)
        self.gen_btn.pack(side="left")

        # copy 按钮
        self.copy_pub_btn = ttk.Button(top, text=t("copy_pub", self.lang), command=self._copy_public, state="disabled")
        self.copy_pub_btn.pack(side="right", padx=(6,0))
        self.copy_priv_btn = ttk.Button(top, text=t("copy_priv", self.lang), command=self._copy_private, state="disabled")
        self.copy_priv_btn.pack(side="right")

        # Keys 显示区
        mid = ttk.Frame(frame)
        mid.pack(fill="both", expand=True, padx=8, pady=6)

        # 公钥
        left = ttk.Frame(mid)
        left.pack(side="left", fill="both", expand=True, padx=(0,4))
        ttk.Label(left, text=t("pubkey_label", self.lang)).pack(anchor="w")
        self.pub_text = ScrolledText(left, height=12)
        self.pub_text.pack(fill="both", expand=True)

        # 私钥
        right = ttk.Frame(mid)
        right.pack(side="left", fill="both", expand=True, padx=(4,0))
        ttk.Label(right, text=t("privkey_label", self.lang)).pack(anchor="w")
        self.priv_text = ScrolledText(right, height=12)
        self.priv_text.pack(fill="both", expand=True)

    # ---------------------------
    #  页：公钥加密
    # ---------------------------
    def _build_tab_encrypt(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=t("tab_encrypt", self.lang))

        upper = ttk.Frame(frame)
        upper.pack(fill="both", expand=False, padx=8, pady=(8,4))

        ttk.Label(upper, text=t("pubkey_label", self.lang)).pack(anchor="w")
        self.enc_pub_text = ScrolledText(upper, height=8)
        self.enc_pub_text.pack(fill="x", expand=True)

        ttk.Label(upper, text=t("plaintext_label", self.lang)).pack(anchor="w", pady=(6,0))
        self.plain_text = ScrolledText(upper, height=8)
        self.plain_text.pack(fill="both", expand=True)

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill="x", padx=8, pady=6)
        self.enc_btn = ttk.Button(btn_row, text=t("encrypt_btn", self.lang), command=self._encrypt_action)
        self.enc_btn.pack(side="left")
        self.enc_copy_out_btn = ttk.Button(btn_row, text=t("copy_out", self.lang), command=lambda: self._copy_text(self.enc_out_text), state="disabled")
        self.enc_copy_out_btn.pack(side="right")

        ttk.Label(frame, text=t("ciphertext_label", self.lang)).pack(anchor="w", padx=8)
        self.enc_out_text = ScrolledText(frame, height=8)
        self.enc_out_text.pack(fill="both", expand=True, padx=8, pady=(0,8))

    # ---------------------------
    #  页：私钥解密
    # ---------------------------
    def _build_tab_decrypt(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=t("tab_decrypt", self.lang))

        ttk.Label(frame, text=t("privkey_label", self.lang)).pack(anchor="w", padx=8, pady=(8,0))
        self.dec_priv_text = ScrolledText(frame, height=8)
        self.dec_priv_text.pack(fill="x", expand=True, padx=8)

        ttk.Label(frame, text=t("ciphertext_label", self.lang)).pack(anchor="w", padx=8, pady=(6,0))
        self.cipher_in_text = ScrolledText(frame, height=8)
        self.cipher_in_text.pack(fill="both", expand=True, padx=8)

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill="x", padx=8, pady=6)
        self.dec_btn = ttk.Button(btn_row, text=t("decrypt_btn", self.lang), command=self._decrypt_action)
        self.dec_btn.pack(side="left")
        self.dec_copy_out_btn = ttk.Button(btn_row, text=t("copy_out", self.lang), command=lambda: self._copy_text(self.dec_out_text), state="disabled")
        self.dec_copy_out_btn.pack(side="right")

        ttk.Label(frame, text=t("plaintext_label", self.lang)).pack(anchor="w", padx=8)
        self.dec_out_text = ScrolledText(frame, height=8)
        self.dec_out_text.pack(fill="both", expand=True, padx=8, pady=(0,8))

    # ---------------------------
    #  语言切换
    # ---------------------------
    def _on_lang_change(self, _ev=None):
        sel = self.lang_box.get()
        self.lang = "zh" if sel == "中文" else "en"
        self._refresh_texts()

    def _refresh_texts(self):
        self.title(t("title", self.lang))
        # notebook tab texts
        self.notebook.tab(0, text=t("tab_generate", self.lang))
        self.notebook.tab(1, text=t("tab_encrypt", self.lang))
        self.notebook.tab(2, text=t("tab_decrypt", self.lang))
        # top labels/buttons
        # rebuild some top-level texts
        # regenerate button labels
        self.gen_btn.config(text=t("generate_btn", self.lang))
        self.copy_pub_btn.config(text=t("copy_pub", self.lang))
        self.copy_priv_btn.config(text=t("copy_priv", self.lang))
        self.enc_btn.config(text=t("encrypt_btn", self.lang))
        self.dec_btn.config(text=t("decrypt_btn", self.lang))
        self.enc_copy_out_btn.config(text=t("copy_out", self.lang))
        self.dec_copy_out_btn.config(text=t("copy_out", self.lang))
        # status label text stays as-is or reset
        self._set_status(t("status_ready", self.lang))

    # ---------------------------
    #  状态、复制
    # ---------------------------
    def _set_status(self, s):
        self.status_var.set(s)

    def _copy_text(self, text_widget):
        txt = text_widget.get("1.0", "end-1c")
        if not txt:
            return
        self.clipboard_clear()
        self.clipboard_append(txt)
        # small feedback
        messagebox.showinfo(t("title", self.lang), "Copied." if self.lang == "en" else "已复制。")

    def _copy_public(self):
        txt = self.pub_text.get("1.0", "end-1c").strip()
        if txt:
            self.clipboard_clear(); self.clipboard_append(txt)
            messagebox.showinfo(t("title", self.lang), "Copied public key." if self.lang=="en" else "已复制公钥。")

    def _copy_private(self):
        txt = self.priv_text.get("1.0", "end-1c").strip()
        if txt:
            self.clipboard_clear(); self.clipboard_append(txt)
            messagebox.showinfo(t("title", self.lang), "Copied private key." if self.lang=="en" else "已复制私钥。")

    # ---------------------------
    #  生成密钥（线程）
    # ---------------------------
    def _generate_keys_thread(self):
        try:
            bits = int(self.keysize_box.get())
        except Exception:
            bits = 1024
        self.gen_btn.config(state="disabled")
        self._set_status(t("status_generating", self.lang))
        threading.Thread(target=self._generate_keys_worker, args=(bits,), daemon=True).start()

    def _generate_keys_worker(self, bits):
        try:
            key = RSA.generate(bits)
            priv = key.export_key()
            pub = key.publickey().export_key()
            # 回到主线程更新 UI
            self.after(0, self._on_keys_generated, pub.decode('utf-8'), priv.decode('utf-8'))
        except Exception as e:
            self.after(0, self._on_generate_error, str(e))

    def _on_keys_generated(self, pub_pem, priv_pem):
        self.last_public_pem = pub_pem
        self.last_private_pem = priv_pem
        self.pub_text.delete("1.0", "end"); self.pub_text.insert("1.0", pub_pem)
        self.priv_text.delete("1.0", "end"); self.priv_text.insert("1.0", priv_pem)
        self.copy_pub_btn.config(state="normal"); self.copy_priv_btn.config(state="normal")
        self.gen_btn.config(state="normal")
        self._set_status(t("ok_generated", self.lang))

    def _on_generate_error(self, errmsg):
        messagebox.showerror(t("title", self.lang), errmsg)
        self.gen_btn.config(state="normal")
        self._set_status(t("status_ready", self.lang))

    # ---------------------------
    #  加密 / 解密 操作
    # ---------------------------
    def _encrypt_action(self):
        pub_pem = self.enc_pub_text.get("1.0", "end-1c").strip()
        if not pub_pem and self.last_public_pem:
            pub_pem = self.last_public_pem  # fallback
        plaintext = self.plain_text.get("1.0", "end-1c").encode('utf-8')
        if not pub_pem:
            messagebox.showwarning(t("title", self.lang), t("err_invalid_key", self.lang))
            return
        try:
            enc_bytes = rsa_encrypt_pem(pub_pem, plaintext)
            enc_b64 = base64.b64encode(enc_bytes).decode('utf-8')
            self.enc_out_text.delete("1.0", "end"); self.enc_out_text.insert("1.0", enc_b64)
            self.enc_copy_out_btn.config(state="normal")
            self._set_status(t("status_ready", self.lang))
        except (ValueError, IndexError) as e:
            messagebox.showerror(t("title", self.lang), t("err_encrypt", self.lang) + "\n" + str(e))
            self._set_status(t("status_ready", self.lang))
        except Exception as e:
            messagebox.showerror(t("title", self.lang), t("err_encrypt", self.lang) + "\n" + str(e))
            self._set_status(t("status_ready", self.lang))

    def _decrypt_action(self):
        priv_pem = self.dec_priv_text.get("1.0", "end-1c").strip()
        if not priv_pem and self.last_private_pem:
            priv_pem = self.last_private_pem  # fallback
        cipher_b64 = self.cipher_in_text.get("1.0", "end-1c").strip()
        if not priv_pem or not cipher_b64:
            messagebox.showwarning(t("title", self.lang), t("err_invalid_key", self.lang))
            return
        try:
            cipher_bytes = base64.b64decode(cipher_b64)
        except Exception:
            messagebox.showerror(t("title", self.lang), t("err_decrypt", self.lang))
            return
        try:
            plain_bytes = rsa_decrypt_pem(priv_pem, cipher_bytes)
            try:
                plain_text = plain_bytes.decode('utf-8')
            except Exception:
                plain_text = plain_bytes.decode('utf-8', errors='replace')
            self.dec_out_text.delete("1.0", "end"); self.dec_out_text.insert("1.0", plain_text)
            self.dec_copy_out_btn.config(state="normal")
            self._set_status(t("status_ready", self.lang))
        except Exception as e:
            messagebox.showerror(t("title", self.lang), t("err_decrypt", self.lang) + "\n" + str(e))
            self._set_status(t("status_ready", self.lang))


# ---------------------------
#  程序入口
# ---------------------------
if __name__ == "__main__":
    app = RSAToolApp()
    app.mainloop()
