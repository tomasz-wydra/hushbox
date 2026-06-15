"""
Hushbox — główna aplikacja GUI.

Układ:
  ┌─────────────────────────────────────────────────────────────┐
  │  TOPBAR                                                      │
  ├──────────────────────┬──────────────────────────────────────┤
  │  SIDEBAR (kontakty)  │  NOTEBOOK (zakładki rozmów)          │
  │                      │  ┌──────────────────────────────────┐│
  │  [+ Dodaj kontakt]   │  │  historia czatu (scrollable)     ││
  │  [kontakt 1] ⋮       │  │                                  ││
  │  [kontakt 2] ⋮       │  ├──────────────────────────────────┤│
  │  ...                 │  │  [▼ Odbierz]  (zwijany panel)    ││
  │                      │  ├──────────────────────────────────┤│
  │                      │  │  [input]  [Wyślij 🔒] [Telegram] ││
  └──────────────────────┴──────────────────────────────────────┘
"""

import json
import threading
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from PIL import Image, ImageTk

from encryption_manager import EncryptionManager
from chat_store import ChatStore, Message
from telegram_transport import TelegramTransport
from app_settings import AppSettings

import sys, logging
if "--log" in sys.argv:
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")


# ─────────────────────────────────────────────────────────────────
# Stałe wizualne
# ─────────────────────────────────────────────────────────────────
FONT_TITLE  = ("Segoe UI", 18, "bold")
FONT_LABEL  = ("Segoe UI", 12)
FONT_MONO   = ("Consolas", 11)
FONT_SMALL  = ("Segoe UI", 10)

COLOR_SENT   = "#1a6b3c"
COLOR_RECV   = "#4fa3e3"
COLOR_CIPHER = "#555555"
COLOR_TG     = "#2196a8"   # akcent dla Telegram

DATA_DIR = "."


# ─────────────────────────────────────────────────────────────────
# Dialog dodawania / edycji kontaktu
# ─────────────────────────────────────────────────────────────────
class ContactDialog(ctk.CTkToplevel):
    """Modal do dodawania / edytowania kontaktu (klucz + dane Telegram)."""

    def __init__(self, parent, title: str,
                 name: str = "", key: str = "",
                 tg_token: str = "", tg_chat_id: str = ""):
        super().__init__(parent)
        self.title(title)
        self.geometry("560x480")
        self.resizable(False, False)
        self.grab_set()
        self.result: tuple | None = None   # (name, key, tg_token, tg_chat_id)

        # ── Nazwa ──
        ctk.CTkLabel(self, text="Contact name:", font=FONT_LABEL).pack(anchor="w", padx=20, pady=(20, 2))
        self.name_entry = ctk.CTkEntry(self, width=520, placeholder_text="e.g. Jan Kowalski")
        self.name_entry.pack(padx=20)
        if name:
            self.name_entry.insert(0, name)

        # ── Klucz publiczny ──
        ctk.CTkLabel(self, text="Public key (base64):", font=FONT_LABEL).pack(anchor="w", padx=20, pady=(14, 2))
        self.key_entry = ctk.CTkEntry(self, width=520, placeholder_text="Paste base64 key or scan QR...")
        self.key_entry.pack(padx=20)
        if key:
            self.key_entry.insert(0, key)

        # ── Separator Telegram ──
        sep_frame = ctk.CTkFrame(self, fg_color="transparent")
        sep_frame.pack(fill="x", padx=20, pady=(18, 4))
        ctk.CTkLabel(sep_frame, text="── Telegram (optional) ──",
                     font=FONT_SMALL, text_color="#888").pack()

        # ── Bot token ──
        ctk.CTkLabel(self, text="Contact's Bot Token (they get it from BotFather):", font=FONT_LABEL).pack(anchor="w", padx=20, pady=(4, 2))
        self.token_entry = ctk.CTkEntry(self, width=520,
                                         placeholder_text="Ask contact for their bot token, e.g. 123456789:ABCdef...")
        self.token_entry.pack(padx=20)
        if tg_token:
            self.token_entry.insert(0, tg_token)

        # ── Chat ID odbiorcy ──
        ctk.CTkLabel(self, text="Contact's Telegram Chat ID (they check via @userinfobot):", font=FONT_LABEL).pack(anchor="w", padx=20, pady=(10, 2))

        chat_id_row = ctk.CTkFrame(self, fg_color="transparent")
        chat_id_row.pack(fill="x", padx=20)

        self.chat_id_entry = ctk.CTkEntry(chat_id_row,
                                           placeholder_text="Ask contact for their Chat ID (from @userinfobot), e.g. 123456789")
        self.chat_id_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        if tg_chat_id:
            self.chat_id_entry.insert(0, tg_chat_id)

        self._detect_btn = ctk.CTkButton(chat_id_row, text="🔍 Detect", width=90,
                                          fg_color="#2a5298", command=self._detect_chat_id)
        self._detect_btn.pack(side="right")

        # ── Przyciski ──
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=20)
        ctk.CTkButton(btn_frame, text="Save", width=120, command=self._save).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Cancel", width=120,
                      fg_color="#555", command=self.destroy).pack(side="left", padx=10)

        self.name_entry.focus()

    def _detect_chat_id(self):
        """Pobierz Chat ID ostatniej osoby która napisała /start do bota."""
        token = self.token_entry.get().strip()
        if not token:
            messagebox.showwarning("No token",
                "Enter Bot Token first, then ask your contact to send /start to your bot.",
                parent=self)
            return
        self._detect_btn.configure(text="⏳...", state="disabled")
        import threading
        def _do():
            try:
                from telegram_transport import TelegramTransport
                tg = TelegramTransport(token)
                chat_id = tg.get_my_chat_id()
                self.after(0, lambda: self._on_detected(chat_id))
            except Exception as e:
                self.after(0, lambda err=e: self._on_detect_error(err))
        threading.Thread(target=_do, daemon=True).start()

    def _on_detected(self, chat_id: str | None):
        self._detect_btn.configure(text="🔍 Detect", state="normal")
        if chat_id:
            self.chat_id_entry.delete(0, "end")
            self.chat_id_entry.insert(0, chat_id)
            messagebox.showinfo("Chat ID detected",
                f"Chat ID set to: {chat_id}", parent=self)
        else:
            messagebox.showwarning("Not found",
                "No messages found.\nAsk your contact to send /start to your bot first.",
                parent=self)

    def _on_detect_error(self, err: Exception):
        self._detect_btn.configure(text="🔍 Detect", state="normal")
        messagebox.showerror("Error", f"Could not fetch Chat ID:\n{err}", parent=self)

    def _save(self):
        name      = self.name_entry.get().strip()
        key       = self.key_entry.get().strip()
        tg_token  = self.token_entry.get().strip()
        tg_chat   = self.chat_id_entry.get().strip()

        if not name:
            messagebox.showerror("Error", "Contact name is required.", parent=self)
            return
        if not key:
            messagebox.showerror("Error", "Public key is required.", parent=self)
            return
        self.result = (name, key, tg_token, tg_chat)
        self.destroy()


# ─────────────────────────────────────────────────────────────────
# Okno QR
# ─────────────────────────────────────────────────────────────────
class QRWindow(ctk.CTkToplevel):
    def __init__(self, parent, public_key_b64: str):
        super().__init__(parent)
        self.title("My Public Key — QR")
        self.geometry("520x580")
        self.resizable(False, False)

        try:
            import segno
            data = json.dumps({"public_key": public_key_b64})
            qr = segno.make(data, error="M")
            qr_path = "my_public_key_qr.png"
            qr.save(qr_path, scale=6, border=2)

            ctk.CTkLabel(self, text="Show this QR to a contact so they can add you.",
                         font=FONT_SMALL).pack(pady=(16, 4))

            img = Image.open(qr_path).resize((320, 320))
            photo = ImageTk.PhotoImage(img)
            lbl = ctk.CTkLabel(self, image=photo, text="")
            lbl.image = photo
            lbl.pack()

            key_box = ctk.CTkTextbox(self, height=80, width=480, font=FONT_MONO)
            key_box.insert("1.0", public_key_b64)
            key_box.configure(state="disabled")
            key_box.pack(pady=10, padx=20)

            ctk.CTkButton(self, text="Copy key",
                          command=lambda: self._copy(public_key_b64)).pack(pady=4)
        except Exception as e:
            ctk.CTkLabel(self, text=f"QR generation error:\n{e}", wraplength=480).pack(pady=30)

        ctk.CTkButton(self, text="Close", fg_color="#555", command=self.destroy).pack(pady=10)

    def _copy(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "Public key copied to clipboard.", parent=self)


# ─────────────────────────────────────────────────────────────────
# Panel "Odbierz wiadomość"
# ─────────────────────────────────────────────────────────────────
class ReceivePanel(ctk.CTkFrame):
    def __init__(self, parent, on_decrypt_cb):
        super().__init__(parent, fg_color="transparent")
        self._on_decrypt = on_decrypt_cb

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x")
        ctk.CTkLabel(header, text="📥 Receive encrypted message", font=FONT_LABEL).pack(side="left", padx=6)
        self._toggle_btn = ctk.CTkButton(header, text="▼ expand", width=90,
                                          fg_color="#444", command=self._toggle)
        self._toggle_btn.pack(side="right", padx=6)

        self._body = ctk.CTkFrame(self, fg_color="transparent")
        self._body_visible = False

        inner = ctk.CTkFrame(self._body, fg_color="transparent")
        inner.pack(fill="x", padx=6, pady=4)

        self.cipher_entry = ctk.CTkEntry(inner,
                                          placeholder_text="Paste base64 ciphertext here...",
                                          font=FONT_MONO)
        self.cipher_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.cipher_entry.bind("<Return>", lambda _: self._on_decrypt(self.cipher_entry.get()))

        ctk.CTkButton(inner, text="Decrypt", width=90,
                      command=lambda: self._on_decrypt(self.cipher_entry.get())).pack(side="right")

    def _toggle(self):
        if self._body_visible:
            self._body.pack_forget()
            self._toggle_btn.configure(text="▼ expand")
        else:
            self._body.pack(fill="x")
            self._toggle_btn.configure(text="▲ collapse")
            self.cipher_entry.focus()
        self._body_visible = not self._body_visible

    def clear(self):
        self.cipher_entry.delete(0, "end")


# ─────────────────────────────────────────────────────────────────
# Zakładka rozmowy z jednym kontaktem
# ─────────────────────────────────────────────────────────────────
class ChatTab(ctk.CTkFrame):
    def __init__(self, parent, contact_name: str,
                 enc_manager: EncryptionManager,
                 chat_store: ChatStore,
                 tg_transport: "TelegramTransport | None"):
        super().__init__(parent, fg_color="transparent")
        self.contact_name = contact_name
        self._enc = enc_manager
        self._store = chat_store
        self._tg = tg_transport
        self._build_ui()
        self._load_history()

    def _build_ui(self):
        # ── Historia ──
        self.history = ctk.CTkTextbox(self, font=FONT_LABEL, state="disabled", wrap="word")
        self.history.pack(fill="both", expand=True, padx=8, pady=(8, 0))

        tb = self.history._textbox
        tb.tag_configure("sent_label",  foreground=COLOR_SENT,  font=(FONT_LABEL[0], FONT_LABEL[1], "bold"))
        tb.tag_configure("sent_text",   foreground=COLOR_SENT)
        tb.tag_configure("recv_label",  foreground=COLOR_RECV,  font=(FONT_LABEL[0], FONT_LABEL[1], "bold"))
        tb.tag_configure("recv_text",   foreground=COLOR_RECV)
        tb.tag_configure("cipher_text", foreground=COLOR_CIPHER, font=(FONT_MONO[0], 9))
        tb.tag_configure("timestamp",   foreground="#888888",    font=(FONT_SMALL[0], 9))
        tb.tag_configure("tg_badge",    foreground=COLOR_TG,     font=(FONT_SMALL[0], 9))
        tb.tag_configure("system_msg",  foreground="#cc8800",    font=(FONT_SMALL[0], 10, "italic"))

        # ── Panel odbierania ──
        self._receive_panel = ReceivePanel(self, on_decrypt_cb=self._handle_decrypt)
        self._receive_panel.pack(fill="x", padx=8, pady=(4, 0))

        # ── Pole wpisywania + przyciski ──
        input_frame = ctk.CTkFrame(self, fg_color="transparent")
        input_frame.pack(fill="x", padx=8, pady=(4, 8))

        self.msg_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text=f"Message to {self.contact_name}...",
            font=FONT_LABEL,
        )
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.msg_entry.bind("<Return>", lambda _: self._send_clipboard())

        self._send_btn = ctk.CTkButton(
            input_frame, text="Send 🔒", width=100, command=self._send_clipboard
        )
        self._send_btn.pack(side="left", padx=(0, 4))

        self._tg_btn = ctk.CTkButton(
            input_frame, text="✈ Telegram", width=110,
            fg_color=COLOR_TG, hover_color="#187a85",
            command=self._send_telegram,
        )
        self._tg_btn.pack(side="left")
        self._update_tg_button_state()

    # ── Ładowanie historii ──────────────────────────────────────

    def _load_history(self):
        for msg in self._store.load(self.contact_name):
            self._render_message(msg, scroll=False)
        self.history.see("end")

    # ── Renderowanie ────────────────────────────────────────────

    def _render_message(self, msg: Message, scroll: bool = True):
        tb = self.history._textbox
        self.history.configure(state="normal")

        via = " [TG]" if getattr(msg, "via_telegram", False) else ""

        if msg.direction == "out":
            tb.insert("end", f"[{msg.timestamp}]", "timestamp")
            if via:
                tb.insert("end", via, "tg_badge")
            tb.insert("end", " You: ", "sent_label")
            tb.insert("end", f"{msg.plaintext}\n", "sent_text")
            tb.insert("end", f"  ╰─ {msg.ciphertext}\n", "cipher_text")
        else:
            tb.insert("end", f"[{msg.timestamp}]", "timestamp")
            if via:
                tb.insert("end", via, "tg_badge")
            tb.insert("end", f" {self.contact_name}: ", "recv_label")
            tb.insert("end", f"{msg.plaintext}\n", "recv_text")

        tb.insert("end", "\n")
        self.history.configure(state="disabled")
        if scroll:
            self.history.see("end")

    def _render_system(self, text: str):
        self.history.configure(state="normal")
        self.history._textbox.insert("end", f"  ℹ {text}\n\n", "system_msg")
        self.history.configure(state="disabled")
        self.history.see("end")

    # ── Wysyłanie — schowek ─────────────────────────────────────

    def _send_clipboard(self):
        text = self.msg_entry.get().strip()
        if not text:
            return
        try:
            cipher = self._enc.encrypt(self.contact_name, text)
        except Exception as e:
            self._render_system(f"Encryption failed: {e}")
            return

        msg = Message(direction="out", plaintext=text, ciphertext=cipher)
        self._store.add_message(self.contact_name, msg)
        self._render_message(msg)
        self.msg_entry.delete(0, "end")

        self.clipboard_clear()
        self.clipboard_append(cipher)
        self._flash_btn(self._send_btn, "✓ Copied!", "#1a6b3c", "Send 🔒")

    # ── Wysyłanie — Telegram ────────────────────────────────────

    def _send_telegram(self):
        text = self.msg_entry.get().strip()
        if not text:
            return

        contact = self._enc.get_contact(self.contact_name)
        if not contact.telegram_bot_token or not contact.telegram_chat_id:
            messagebox.showwarning(
                "Telegram not configured",
                f"Set Bot Token and Chat ID for '{self.contact_name}'\n"
                "in the contact edit dialog (⋮ → Edit).",
                parent=self,
            )
            return

        try:
            cipher = self._enc.encrypt(self.contact_name, text)
        except Exception as e:
            self._render_system(f"Encryption failed: {e}")
            return

        def _do_send():
            try:
                tg = TelegramTransport(contact.telegram_bot_token)
                tg.send(contact.telegram_chat_id, cipher)
                msg = Message(direction="out", plaintext=text,
                              ciphertext=cipher, via_telegram=True)
                self._store.add_message(self.contact_name, msg)
                # GUI update musi być w głównym wątku
                self.after(0, lambda: self._on_tg_sent(msg))
            except Exception as e:
                self.after(0, lambda err=e: self._render_system(f"Telegram error: {err}"))

        threading.Thread(target=_do_send, daemon=True).start()
        self.msg_entry.delete(0, "end")
        self._flash_btn(self._tg_btn, "⏳ Sending...", "#555", "✈ Telegram",
                        restore_color=COLOR_TG)

    def _on_tg_sent(self, msg: Message):
        self._render_message(msg)
        self._flash_btn(self._tg_btn, "✓ Sent!", "#1a6b3c", "✈ Telegram",
                        restore_color=COLOR_TG)

    # ── Odbieranie (deszyfrowanie) ───────────────────────────────

    def _handle_decrypt(self, cipher_text: str, via_telegram: bool = False):
        cipher_text = cipher_text.strip()
        if not cipher_text:
            return
        try:
            plaintext = self._enc.decrypt(self.contact_name, cipher_text)
        except Exception as e:
            self._render_system(f"Decryption failed: {e}")
            return

        msg = Message(direction="in", plaintext=plaintext,
                      ciphertext=cipher_text, via_telegram=via_telegram)
        self._store.add_message(self.contact_name, msg)
        self._render_message(msg)
        self._receive_panel.clear()

    # ── Telegram polling callback ────────────────────────────────

    def on_telegram_message(self, cipher_text: str):
        """Wywoływane z wątku pollingu gdy przyjdzie nowa wiadomość."""
        self.after(0, lambda: self._handle_decrypt(cipher_text, via_telegram=True))

    # ── Helpers ──────────────────────────────────────────────────

    def _update_tg_button_state(self):
        try:
            c = self._enc.get_contact(self.contact_name)
            configured = bool(c.telegram_bot_token and c.telegram_chat_id)
        except Exception:
            configured = False
        self._tg_btn.configure(
            state="normal" if configured else "disabled",
            fg_color=COLOR_TG if configured else "#444",
        )

    def refresh_tg_state(self):
        self._update_tg_button_state()

    def _flash_btn(self, btn, temp_text, temp_color, orig_text,
                   restore_color=None, delay=1800):
        btn.configure(text=temp_text, fg_color=temp_color)
        rc = restore_color or ["#3B8ED0", "#1F6AA5"]
        self.after(delay, lambda: btn.configure(text=orig_text, fg_color=rc))

    def clear_history(self):
        self._store.clear_history(self.contact_name)
        self.history.configure(state="normal")
        self.history.delete("1.0", "end")
        self.history.configure(state="disabled")

    def focus_input(self):
        self.msg_entry.focus()


# ─────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────
class ContactSidebar(ctk.CTkFrame):
    def __init__(self, parent, on_open_cb, on_add_cb, on_edit_cb, on_delete_cb):
        super().__init__(parent, width=220, corner_radius=0)
        self.pack_propagate(False)
        self._on_open   = on_open_cb
        self._on_add    = on_add_cb
        self._on_edit   = on_edit_cb
        self._on_delete = on_delete_cb
        self._buttons: dict[str, ctk.CTkButton] = {}
        self._active: str | None = None
        self._build()

    def _build(self):
        ctk.CTkLabel(self, text="Contacts", font=FONT_TITLE).pack(pady=(16, 8))

        # przycisk na dole — pakowany PRZED ScrollableFrame, żeby nie był przykryty
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(side="bottom", fill="x", padx=6, pady=8)
        ctk.CTkButton(btn_frame, text="+ Add contact",
                      command=self._on_add).pack(fill="x")

        self._list_frame = ctk.CTkScrollableFrame(self, label_text="")
        self._list_frame.pack(fill="both", expand=True, padx=6, pady=4)

    def refresh(self, contacts: list[str], tg_status: dict[str, bool],
                active: str | None = None):
        for w in self._list_frame.winfo_children():
            w.destroy()
        self._buttons.clear()

        for name in contacts:
            row = ctk.CTkFrame(self._list_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)

            # ikona Telegram jeśli skonfigurowany
            tg_icon = " ✈" if tg_status.get(name) else ""
            label = f"{name}{tg_icon}"

            btn = ctk.CTkButton(
                row, text=label, anchor="w",
                fg_color="#2a5298" if name == active else "transparent",
                text_color="white" if name == active else ["gray10", "gray90"],
                hover_color="#2a5298",
                command=lambda n=name: self._on_open(n),
            )
            btn.pack(side="left", fill="x", expand=True)

            menu_btn = ctk.CTkButton(row, text="⋮", width=28,
                                      fg_color="transparent", hover_color="#444",
                                      command=lambda n=name: self._show_menu(n))
            menu_btn.pack(side="right")
            self._buttons[name] = btn

        self._active = active

    def set_active(self, name: str | None):
        self._active = name
        for n, btn in self._buttons.items():
            is_active = (n == name)
            btn.configure(
                fg_color="#2a5298" if is_active else "transparent",
                text_color="white" if is_active else ["gray10", "gray90"],
            )

    def _show_menu(self, name: str):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Open chat",    command=lambda: self._on_open(name))
        menu.add_command(label="Edit contact", command=lambda: self._on_edit(name))
        menu.add_separator()
        menu.add_command(label="Delete contact", command=lambda: self._on_delete(name))
        menu.tk_popup(*self.winfo_pointerxy())


# ─────────────────────────────────────────────────────────────────
# Okno ustawień aplikacji
# ─────────────────────────────────────────────────────────────────
class SettingsWindow(ctk.CTkToplevel):
    """Globalane ustawienia aplikacji — m.in. własny token Telegram."""

    def __init__(self, parent, settings: AppSettings, on_save_cb):
        super().__init__(parent)
        self.title("Settings")
        self.geometry("540x280")
        self.resizable(False, False)
        self.grab_set()
        self._settings = settings
        self._on_save = on_save_cb

        # ── Sekcja Telegram ──
        ctk.CTkLabel(self, text="Telegram", font=FONT_TITLE).pack(anchor="w", padx=20, pady=(20, 4))

        ctk.CTkLabel(
            self,
            text="Your Bot Token — contacts send messages TO your bot, you receive them automatically.",
            font=FONT_SMALL, text_color="#aaa", wraplength=500, justify="left",
        ).pack(anchor="w", padx=20)

        token_row = ctk.CTkFrame(self, fg_color="transparent")
        token_row.pack(fill="x", padx=20, pady=(8, 0))

        ctk.CTkLabel(token_row, text="My Bot Token:", font=FONT_LABEL, width=130).pack(side="left")
        self._token_entry = ctk.CTkEntry(
            token_row, placeholder_text="123456789:ABCdef...  (from BotFather)"
        )
        self._token_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
        if settings.my_bot_token:
            self._token_entry.insert(0, settings.my_bot_token)

        ctk.CTkLabel(
            self,
            text="Get it from @BotFather → /newbot. Share your bot name (not the token!) with contacts.",
            font=FONT_SMALL, text_color="#666", wraplength=500, justify="left",
        ).pack(anchor="w", padx=20, pady=(6, 0))

        # ── Przyciski ──
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=24)
        ctk.CTkButton(btn_frame, text="Save", width=120, command=self._save).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Cancel", width=120,
                      fg_color="#555", command=self.destroy).pack(side="left", padx=10)

        self._token_entry.focus()

    def _save(self):
        token = self._token_entry.get().strip()
        self._settings.my_bot_token = token
        self._on_save()
        self.destroy()


# ─────────────────────────────────────────────────────────────────
# Menadżer pollerów Telegram (jeden per kontakt)
# ─────────────────────────────────────────────────────────────────
class TelegramPollerManager:
    """Zarządza wątkami pollingu dla wielu kontaktów jednocześnie."""

    def __init__(self):
        self._pollers: dict[str, TelegramTransport] = {}

    def start(self, contact_name: str, bot_token: str,
              on_message_cb, last_update_id: int = 0,
              on_update_id_change=None) -> None:
        """Uruchom polling dla kontaktu. Jeśli już działa — zrestartuj."""
        self.stop(contact_name)
        tg = TelegramTransport(bot_token,
                               last_update_id=last_update_id,
                               on_update_id_change=on_update_id_change)
        tg.on_message = lambda chat_id, text: on_message_cb(contact_name, chat_id, text)
        tg.start_polling()
        self._pollers[contact_name] = tg

    def stop(self, contact_name: str) -> None:
        if contact_name in self._pollers:
            self._pollers[contact_name].stop_polling()
            del self._pollers[contact_name]

    def stop_all(self) -> None:
        for name in list(self._pollers):
            self.stop(name)

    def is_running(self, contact_name: str) -> bool:
        p = self._pollers.get(contact_name)
        return bool(p and p.is_polling)


# ─────────────────────────────────────────────────────────────────
# Główne okno
# ─────────────────────────────────────────────────────────────────
class HushboxApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Hushbox 🔐")
        self.geometry("1200x720")
        self.minsize(900, 580)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._enc      = EncryptionManager(data_dir=DATA_DIR)
        self._store    = ChatStore(data_dir=DATA_DIR)
        self._settings = AppSettings(data_dir=DATA_DIR)
        self._pollers  = TelegramPollerManager()
        self._tabs: dict[str, ChatTab] = {}

        self._build_layout()
        self._refresh_contacts()
        self._start_my_poller()

    # ── Layout ───────────────────────────────────────────────────

    def _build_layout(self):
        # Topbar
        top = ctk.CTkFrame(self, height=44, corner_radius=0, fg_color="#1a1a2e")
        top.pack(fill="x")
        top.pack_propagate(False)

        ctk.CTkLabel(top, text="Hushbox 🔐", font=FONT_TITLE,
                     text_color="white").pack(side="left", padx=16)

        ctk.CTkButton(top, text="📱 My QR", width=100,
                      fg_color="#2a5298",
                      command=self._show_qr).pack(side="right", padx=6, pady=5)
        ctk.CTkButton(top, text="📷 Import QR", width=120,
                      fg_color="#555",
                      command=self._import_qr).pack(side="right", padx=2, pady=5)
        ctk.CTkButton(top, text="⚙ Settings", width=100,
                      fg_color="#555",
                      command=self._open_settings).pack(side="right", padx=2, pady=5)

        # Status bar Telegram (dolny pasek)
        self._status_var = tk.StringVar(value="")
        status_bar = ctk.CTkLabel(self, textvariable=self._status_var,
                                   font=FONT_SMALL, text_color="#888",
                                   anchor="w")
        status_bar.pack(fill="x", padx=10, side="bottom")

        # Body
        body = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        body.pack(fill="both", expand=True)

        self._sidebar = ContactSidebar(
            body,
            on_open_cb=self._open_chat,
            on_add_cb=self._add_contact,
            on_edit_cb=self._edit_contact,
            on_delete_cb=self._delete_contact,
        )
        self._sidebar.pack(side="left", fill="y")

        tab_area = ctk.CTkFrame(body, fg_color="transparent")
        tab_area.pack(side="left", fill="both", expand=True)

        self._notebook = ctk.CTkTabview(tab_area)
        self._notebook.pack(fill="both", expand=True, padx=6, pady=6)

        self._welcome = ctk.CTkFrame(tab_area, fg_color="transparent")
        ctk.CTkLabel(
            self._welcome,
            text="Select a contact to start a conversation\nor add a new one with '+ Add contact'.",
            font=FONT_LABEL, justify="center",
        ).pack(expand=True)
        self._welcome.pack(fill="both", expand=True)
        self._notebook.pack_forget()

    # ── Kontakty ─────────────────────────────────────────────────

    def _tg_status(self) -> dict[str, bool]:
        return {
            name: bool(self._enc.get_contact(name).telegram_bot_token
                       and self._enc.get_contact(name).telegram_chat_id)
            for name in self._enc.list_contacts()
        }

    def _refresh_contacts(self, active: str | None = None):
        contacts = self._enc.list_contacts()
        self._sidebar.refresh(contacts, self._tg_status(),
                               active=active or self._current_contact())

    def _current_contact(self) -> str | None:
        try:
            return self._notebook.get()
        except Exception:
            return None

    def _add_contact(self):
        dlg = ContactDialog(self, title="Add contact")
        self.wait_window(dlg)
        if dlg.result:
            name, key, tg_token, tg_chat = dlg.result
            try:
                self._enc.add_contact(name, key, tg_token, tg_chat)
                self._refresh_contacts()
                self._restart_poller(name)
                self._open_chat(name)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self)

    def _edit_contact(self, name: str):
        c = self._enc.get_contact(name)
        dlg = ContactDialog(self, title="Edit contact",
                             name=name, key=c.public_key,
                             tg_token=c.telegram_bot_token,
                             tg_chat_id=c.telegram_chat_id)
        self.wait_window(dlg)
        if dlg.result:
            new_name, new_key, tg_token, tg_chat = dlg.result
            try:
                if new_name != name:
                    self._enc.rename_contact(name, new_name)
                    old_p = self._store._path(name)
                    new_p = self._store._path(new_name)
                    if old_p.exists():
                        old_p.rename(new_p)
                    self._pollers.stop(name)
                    self._close_tab(name)
                    name = new_name
                self._enc.add_contact(name, new_key, tg_token, tg_chat)
                self._refresh_contacts()
                self._restart_poller(name)
                if name in self._tabs:
                    self._tabs[name].refresh_tg_state()
                self._open_chat(name)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self)

    def _delete_contact(self, name: str):
        if not messagebox.askyesno(
            "Delete contact",
            f"Delete '{name}'?\nChat history will be preserved.",
            parent=self,
        ):
            return
        try:
            self._enc.remove_contact(name)
            self._pollers.stop(name)
            self._close_tab(name)
            self._refresh_contacts()
        except Exception as e:
            messagebox.showerror("Error", str(e), parent=self)

    # ── Zakładki ─────────────────────────────────────────────────

    def _open_chat(self, name: str):
        self._welcome.pack_forget()
        self._notebook.pack(fill="both", expand=True, padx=6, pady=6)

        if name not in self._tabs:
            self._notebook.add(name)
            frame = self._notebook.tab(name)
            tab = ChatTab(frame, name, self._enc, self._store, None)
            tab.pack(fill="both", expand=True)
            self._tabs[name] = tab

        self._notebook.set(name)
        self._sidebar.set_active(name)
        self._tabs[name].focus_input()

    def _close_tab(self, name: str):
        if name in self._tabs:
            try:
                self._notebook.delete(name)
            except Exception:
                pass
            del self._tabs[name]
        if not self._tabs:
            self._notebook.pack_forget()
            self._welcome.pack(fill="both", expand=True)

    # ── Telegram polling ─────────────────────────────────────────

    def _start_my_poller(self):
        """Uruchom polling na własnym bocie (odbiór wiadomości od kontaktów)."""
        token = self._settings.my_bot_token
        if token:
            self._pollers.start(
                "__self__", token, self._on_tg_message,
                last_update_id=self._settings.last_update_id,
                on_update_id_change=lambda uid: setattr(self._settings, "last_update_id", uid),
            )
            self._set_status("Telegram: receiving on your bot")
        else:
            self._set_status("Telegram: set your Bot Token in ⚙ Settings to enable auto-receive")

    def _restart_poller(self, name: str):
        """Polling odbywa się tylko na własnym bocie — nie per kontakt."""
        pass

    def _open_settings(self):
        SettingsWindow(self, self._settings, on_save_cb=self._on_settings_saved)

    def _on_settings_saved(self):
        self._pollers.stop_all()
        self._start_my_poller()

    def _on_tg_message(self, contact_name: str, chat_id: str, cipher_text: str):
        """Callback z wątku pollingu — musi delegować do GUI przez after()."""
        self.after(0, lambda: self._dispatch_tg_message(contact_name, chat_id, cipher_text))

    def _dispatch_tg_message(self, contact_name: str, chat_id: str, cipher_text: str):
        # znajdź kontakt po chat_id nadawcy, ignorując contact_name z pollera
        # (jeden bot może odbierać od wielu kontaktów)
        resolved = self._resolve_contact_by_chat_id(chat_id) or contact_name
        if resolved not in self._tabs:
            self._open_chat(resolved)
        self._tabs[resolved].on_telegram_message(cipher_text)
        self._set_status(f"New Telegram message from {resolved}")

    def _resolve_contact_by_chat_id(self, chat_id: str) -> str | None:
        """Znajdź nazwę kontaktu na podstawie jego telegram_chat_id."""
        import logging
        log = logging.getLogger(__name__)
        for name in self._enc.list_contacts():
            try:
                stored = self._enc.get_contact(name).telegram_chat_id
                log.debug(f"[TG] resolve: contact={name!r}, stored_chat_id={stored!r}, incoming={chat_id!r}, match={stored == chat_id}")
                if stored == chat_id:
                    return name
            except Exception:
                pass
        log.warning(f"[TG] no contact found for chat_id={chat_id!r}")
        return None

    def _set_status(self, text: str):
        self._status_var.set(f"  {text}")

    # ── QR ───────────────────────────────────────────────────────

    def _show_qr(self):
        QRWindow(self, self._enc.export_public_key())

    def _import_qr(self):
        raw = ""
        try:
            raw = self.clipboard_get().strip()
        except Exception:
            pass

        if not raw:
            messagebox.showinfo(
                "Import key",
                "Copy a public key (base64 or JSON from QR) to clipboard,\n"
                "then click this button again.",
                parent=self,
            )
            return

        public_key = raw
        try:
            data = json.loads(raw)
            public_key = data.get("public_key", raw)
        except Exception:
            pass

        dlg = ContactDialog(self, title="Add contact from QR", key=public_key)
        self.wait_window(dlg)
        if dlg.result:
            name, key, tg_token, tg_chat = dlg.result
            try:
                self._enc.add_contact(name, key, tg_token, tg_chat)
                self._refresh_contacts()
                self._restart_poller(name)
                self._open_chat(name)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self)

    # ── Zamknięcie ───────────────────────────────────────────────

    def _on_close(self):
        self._pollers.stop_all()
        self.destroy()


# ─────────────────────────────────────────────────────────────────
# Start
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    HushboxApp().mainloop()
