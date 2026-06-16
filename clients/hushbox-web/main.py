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
  │                      │  │  [input]  [Wyślij 🔒] [Send 📡]  ││
  └──────────────────────┴──────────────────────────────────────┘
"""

import json
import threading
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from PIL import Image, ImageTk

from hushbox_core import EncryptionManager, ChatStore, Message, RelayTransport, pubkey_to_hash, AppSettings
from hushbox_core.encryption_manager import ContactInfo


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
COLOR_RELAY  = "#8e44ad"   # akcent dla relay

DATA_DIR = "."


# ─────────────────────────────────────────────────────────────────
# Dialog dodawania / edycji kontaktu
# ─────────────────────────────────────────────────────────────────
class ContactDialog(ctk.CTkToplevel):
    """Modal do dodawania / edytowania kontaktu (klucz + relay URL)."""

    def __init__(self, parent, title: str,
                 name: str = "", key: str = "",
                 relay_url: str = ""):
        super().__init__(parent)
        self.title(title)
        self.geometry("560x400")
        self.resizable(False, False)
        self.grab_set()
        self.result: tuple | None = None   # (name, key, relay_url)

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

        # ── Separator relay ──
        sep_frame = ctk.CTkFrame(self, fg_color="transparent")
        sep_frame.pack(fill="x", padx=20, pady=(18, 4))
        ctk.CTkLabel(sep_frame, text="── Relay (optional — overrides global setting) ──",
                     font=FONT_SMALL, text_color="#888").pack()

        # ── Relay URL override per kontakt ──
        ctk.CTkLabel(self, text="Relay URL (leave empty to use global):", font=FONT_LABEL).pack(anchor="w", padx=20, pady=(4, 2))
        self.relay_entry = ctk.CTkEntry(self, width=520,
                                         placeholder_text="https://relay.twoja-domena.pl")
        self.relay_entry.pack(padx=20)
        if relay_url:
            self.relay_entry.insert(0, relay_url)

        # ── Przyciski ──
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=24)
        ctk.CTkButton(btn_frame, text="Save", width=120, command=self._save).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Cancel", width=120,
                      fg_color="#555", command=self.destroy).pack(side="left", padx=10)

        self.name_entry.focus()

    def _save(self):
        name      = self.name_entry.get().strip()
        key       = self.key_entry.get().strip()
        relay_url = self.relay_entry.get().strip()

        if not name:
            messagebox.showerror("Error", "Contact name is required.", parent=self)
            return
        if not key:
            messagebox.showerror("Error", "Public key is required.", parent=self)
            return
        self.result = (name, key, relay_url)
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
                 relay: "RelayTransport | None"):
        super().__init__(parent, fg_color="transparent")
        self.contact_name = contact_name
        self._enc   = enc_manager
        self._store = chat_store
        self._relay = relay
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
        tb.tag_configure("relay_badge", foreground=COLOR_RELAY,  font=(FONT_SMALL[0], 9))
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

        self._relay_btn = ctk.CTkButton(
            input_frame, text="Send 📡", width=100,
            fg_color=COLOR_RELAY, hover_color="#6c3483",
            command=self._send_relay,
        )
        self._relay_btn.pack(side="left")
        self._update_relay_button_state()

    # ── Ładowanie historii ──────────────────────────────────────

    def _load_history(self):
        for msg in self._store.load(self.contact_name):
            self._render_message(msg, scroll=False)
        self.history.see("end")

    # ── Renderowanie ────────────────────────────────────────────

    def _render_message(self, msg: Message, scroll: bool = True):
        tb = self.history._textbox
        self.history.configure(state="normal")

        via = " [📡]" if getattr(msg, "via_telegram", False) else ""

        if msg.direction == "out":
            tb.insert("end", f"[{msg.timestamp}]", "timestamp")
            if via:
                tb.insert("end", via, "relay_badge")
            tb.insert("end", " You: ", "sent_label")
            tb.insert("end", f"{msg.plaintext}\n", "sent_text")
            tb.insert("end", f"  ╰─ {msg.ciphertext}\n", "cipher_text")
        else:
            tb.insert("end", f"[{msg.timestamp}]", "timestamp")
            if via:
                tb.insert("end", via, "relay_badge")
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

    # ── Wysyłanie — relay ───────────────────────────────────────

    def _send_relay(self):
        text = self.msg_entry.get().strip()
        if not text:
            return

        if not self._relay:
            messagebox.showwarning(
                "Relay not configured",
                "Set Relay URL in ⚙ Settings to enable automatic delivery.",
                parent=self,
            )
            return

        contact = self._enc.get_contact(self.contact_name)

        try:
            cipher = self._enc.encrypt(self.contact_name, text)
        except Exception as e:
            self._render_system(f"Encryption failed: {e}")
            return

        def _do_send():
            try:
                self._relay.send(
                    recipient_pubkey_b64=contact.public_key,
                    payload=cipher,
                    sender_pubkey_b64=self._enc.export_public_key(),
                )
                msg = Message(direction="out", plaintext=text,
                              ciphertext=cipher, via_telegram=True)
                self._store.add_message(self.contact_name, msg)
                self.after(0, lambda: self._on_relay_sent(msg))
            except Exception as e:
                self.after(0, lambda err=e: self._render_system(f"Relay error: {err}"))

        threading.Thread(target=_do_send, daemon=True).start()
        self.msg_entry.delete(0, "end")
        self._flash_btn(self._relay_btn, "⏳ Sending...", "#555", "Send 📡",
                        restore_color=COLOR_RELAY)

    def _on_relay_sent(self, msg: Message):
        self._render_message(msg)
        self._flash_btn(self._relay_btn, "✓ Sent!", "#1a6b3c", "Send 📡",
                        restore_color=COLOR_RELAY)

    # ── Odbieranie (deszyfrowanie) ───────────────────────────────

    def _handle_decrypt(self, cipher_text: str, via_relay: bool = False):
        cipher_text = cipher_text.strip()
        if not cipher_text:
            return
        try:
            plaintext = self._enc.decrypt(self.contact_name, cipher_text)
        except Exception as e:
            self._render_system(f"Decryption failed: {e}")
            return

        msg = Message(direction="in", plaintext=plaintext,
                      ciphertext=cipher_text, via_telegram=via_relay)
        self._store.add_message(self.contact_name, msg)
        self._render_message(msg)
        self._receive_panel.clear()

    # ── Relay polling callback ───────────────────────────────────

    def on_relay_message(self, cipher_text: str):
        """Wywoływane z wątku pollingu gdy przyjdzie nowa wiadomość."""
        self.after(0, lambda: self._handle_decrypt(cipher_text, via_relay=True))

    # ── Helpers ──────────────────────────────────────────────────

    def _update_relay_button_state(self):
        # przycisk relay aktywny gdy jest relay transport
        configured = self._relay is not None
        self._relay_btn.configure(
            state="normal" if configured else "disabled",
            fg_color=COLOR_RELAY if configured else "#444",
        )

    def refresh_relay_state(self, relay: "RelayTransport | None"):
        self._relay = relay
        self._update_relay_button_state()

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

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(side="bottom", fill="x", padx=6, pady=8)
        ctk.CTkButton(btn_frame, text="+ Add contact",
                      command=self._on_add).pack(fill="x")

        self._list_frame = ctk.CTkScrollableFrame(self, label_text="")
        self._list_frame.pack(fill="both", expand=True, padx=6, pady=4)

    def refresh(self, contacts: list[str], relay_status: dict[str, bool],
                active: str | None = None):
        for w in self._list_frame.winfo_children():
            w.destroy()
        self._buttons.clear()

        for name in contacts:
            row = ctk.CTkFrame(self._list_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)

            relay_icon = " 📡" if relay_status.get(name) else ""
            label = f"{name}{relay_icon}"

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
    """Globalne ustawienia aplikacji — relay URL."""

    def __init__(self, parent, settings: AppSettings, on_save_cb):
        super().__init__(parent)
        self.title("Settings")
        self.geometry("540x280")
        self.resizable(False, False)
        self.grab_set()
        self._settings = settings
        self._on_save  = on_save_cb

        # ── Sekcja Relay ──
        ctk.CTkLabel(self, text="Relay Server", font=FONT_TITLE).pack(anchor="w", padx=20, pady=(20, 4))

        ctk.CTkLabel(
            self,
            text="Messages are delivered via your own relay server — no Telegram required.",
            font=FONT_SMALL, text_color="#aaa", wraplength=500, justify="left",
        ).pack(anchor="w", padx=20)

        url_row = ctk.CTkFrame(self, fg_color="transparent")
        url_row.pack(fill="x", padx=20, pady=(8, 0))

        ctk.CTkLabel(url_row, text="Relay URL:", font=FONT_LABEL, width=100).pack(side="left")
        self._url_entry = ctk.CTkEntry(
            url_row, placeholder_text="https://relay.twoja-domena.pl"
        )
        self._url_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
        if settings.relay_url:
            self._url_entry.insert(0, settings.relay_url)

        ctk.CTkLabel(
            self,
            text="Run docker-compose up -d in the relay_server/ directory to start your relay.",
            font=FONT_SMALL, text_color="#666", wraplength=500, justify="left",
        ).pack(anchor="w", padx=20, pady=(6, 0))

        # ── Przyciski ──
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=24)
        ctk.CTkButton(btn_frame, text="Save", width=120, command=self._save).pack(side="left", padx=10)
        ctk.CTkButton(btn_frame, text="Cancel", width=120,
                      fg_color="#555", command=self.destroy).pack(side="left", padx=10)

        self._url_entry.focus()

    def _save(self):
        self._settings.relay_url = self._url_entry.get().strip()
        self._on_save()
        self.destroy()


# ─────────────────────────────────────────────────────────────────
# Menadżer pollera relay
# ─────────────────────────────────────────────────────────────────
class RelayPollerManager:
    """Zarządza pojedynczym wątkiem long-polling relay."""

    def __init__(self):
        self._transport: RelayTransport | None = None

    def start(self, relay_url: str, my_pubkey_b64: str,
              on_message_cb,
              last_message_id: str = "",
              on_last_id_change=None) -> RelayTransport:
        self.stop()
        t = RelayTransport(
            relay_url=relay_url,
            my_pubkey_b64=my_pubkey_b64,
            last_message_id=last_message_id,
            on_last_id_change=on_last_id_change,
        )
        t.on_message = on_message_cb
        t.start_polling()
        self._transport = t
        return t

    def stop(self) -> None:
        if self._transport:
            self._transport.stop_polling()
            self._transport = None

    @property
    def transport(self) -> RelayTransport | None:
        return self._transport

    @property
    def is_running(self) -> bool:
        return bool(self._transport and self._transport.is_polling)


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
        self._poller   = RelayPollerManager()
        self._tabs: dict[str, ChatTab] = {}

        self._build_layout()
        self._refresh_contacts()
        self._start_relay_poller()

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

        # Status bar (dolny pasek)
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

    def _relay_status(self) -> dict[str, bool]:
        """Kontakt ma relay jeśli używa globalnego relay URL lub ma override."""
        global_ok = bool(self._settings.relay_url)
        return {
            name: global_ok or bool(self._enc.get_contact(name).relay_url)
            for name in self._enc.list_contacts()
        }

    def _refresh_contacts(self, active: str | None = None):
        contacts = self._enc.list_contacts()
        self._sidebar.refresh(contacts, self._relay_status(),
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
            name, key, relay_url = dlg.result
            try:
                self._enc.add_contact(name, key, relay_url=relay_url)
                self._refresh_contacts()
                self._open_chat(name)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self)

    def _edit_contact(self, name: str):
        c = self._enc.get_contact(name)
        dlg = ContactDialog(self, title="Edit contact",
                             name=name, key=c.public_key,
                             relay_url=c.relay_url)
        self.wait_window(dlg)
        if dlg.result:
            new_name, new_key, relay_url = dlg.result
            try:
                if new_name != name:
                    self._enc.rename_contact(name, new_name)
                    old_p = self._store._path(name)
                    new_p = self._store._path(new_name)
                    if old_p.exists():
                        old_p.rename(new_p)
                    self._close_tab(name)
                    name = new_name
                self._enc.add_contact(name, new_key, relay_url=relay_url)
                self._refresh_contacts()
                if name in self._tabs:
                    self._tabs[name].refresh_relay_state(self._poller.transport)
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
            tab = ChatTab(frame, name, self._enc, self._store,
                          relay=self._poller.transport)
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

    # ── Relay polling ─────────────────────────────────────────────

    def _start_relay_poller(self):
        url = self._settings.relay_url
        if not url:
            self._set_status("Relay: set Relay URL in ⚙ Settings to enable auto-receive")
            return

        transport = self._poller.start(
            relay_url=url,
            my_pubkey_b64=self._enc.export_public_key(),
            on_message_cb=self._on_relay_message,
            last_message_id=self._settings.last_message_id,
            on_last_id_change=lambda mid: setattr(self._settings, "last_message_id", mid),
        )
        # zaktualizuj transport we wszystkich otwartych zakładkach
        for tab in self._tabs.values():
            tab.refresh_relay_state(transport)
        self._set_status(f"Relay: connected to {url}")

    def _open_settings(self):
        SettingsWindow(self, self._settings, on_save_cb=self._on_settings_saved)

    def _on_settings_saved(self):
        self._poller.stop()
        self._start_relay_poller()
        self._refresh_contacts()

    def _on_relay_message(self, from_hash: str, payload: str):
        """Callback z wątku pollingu — deleguj do GUI przez after()."""
        self.after(0, lambda: self._dispatch_relay_message(from_hash, payload))

    def _dispatch_relay_message(self, from_hash: str, payload: str):
        resolved = self._enc.find_contact_by_pubkey_hash(from_hash)
        if not resolved:
            # nieznany nadawca — pokaż w pierwszej otwartej zakładce lub zignoruj
            import logging
            logging.getLogger(__name__).warning(
                f"[Relay] unknown sender hash={from_hash[:8]}..."
            )
            return

        if resolved not in self._tabs:
            self._open_chat(resolved)
        self._tabs[resolved].on_relay_message(payload)
        self._set_status(f"New message from {resolved}")

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
            name, key, relay_url = dlg.result
            try:
                self._enc.add_contact(name, key, relay_url=relay_url)
                self._refresh_contacts()
                self._open_chat(name)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=self)

    # ── Zamknięcie ───────────────────────────────────────────────

    def _on_close(self):
        self._poller.stop()
        self.destroy()


# ─────────────────────────────────────────────────────────────────
# Start
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    HushboxApp().mainloop()
