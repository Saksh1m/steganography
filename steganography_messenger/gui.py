"""Tkinter-based GUI for the Steganography Messenger application."""
from __future__ import annotations

import os
import threading
from pathlib import Path
from tkinter import BOTH, END, LEFT, X, Canvas, Frame, Label, StringVar, Text, Tk
from tkinter import messagebox
from tkinter import filedialog
from tkinter import ttk

from PIL import Image, ImageTk

from . import crypto_utils
from .stego import build_payload, embed_payload, extract_payload, parse_payload


class SteganographyMessengerApp:
    """Main application controller."""

    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("Steganography Messenger")
        self.root.geometry("900x620")
        self.root.minsize(900, 620)

        self.public_key_path = StringVar()
        self.private_key_path = StringVar()
        self.encode_image_path = StringVar()
        self.decode_image_path = StringVar()
        self.output_image_path = StringVar()
        self.password_var = StringVar()
        self.decode_password_var = StringVar()

        self.encode_preview = None
        self.decode_preview = None

        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction helpers
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)

        encode_frame = Frame(notebook)
        decode_frame = Frame(notebook)
        notebook.add(encode_frame, text="Encode")
        notebook.add(decode_frame, text="Decode")

        self._build_encode_tab(encode_frame)
        self._build_decode_tab(decode_frame)

    def _build_encode_tab(self, parent: Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        top_frame = Frame(parent)
        top_frame.pack(fill=X, pady=5)

        Label(top_frame, text="Cover image:").pack(side=LEFT)
        ttk.Entry(top_frame, textvariable=self.encode_image_path, width=50).pack(side=LEFT, padx=5)
        ttk.Button(top_frame, text="Browse", command=self._select_encode_image).pack(side=LEFT)

        preview_frame = Frame(parent)
        preview_frame.pack(fill=X, pady=5)
        Label(preview_frame, text="Preview:").pack(anchor="w")
        self.encode_canvas = Canvas(preview_frame, width=320, height=240, bg="#f0f0f0")
        self.encode_canvas.pack()

        message_frame = Frame(parent)
        message_frame.pack(fill=BOTH, expand=True, pady=5)
        Label(message_frame, text="Secret message:").pack(anchor="w")
        self.message_text = Text(message_frame, height=8, wrap="word")
        self.message_text.pack(fill=BOTH, expand=True)

        key_frame = Frame(parent)
        key_frame.pack(fill=X, pady=5)
        Label(key_frame, text="RSA public key:").pack(side=LEFT)
        ttk.Entry(key_frame, textvariable=self.public_key_path, width=45).pack(side=LEFT, padx=5)
        ttk.Button(key_frame, text="Browse", command=self._select_public_key).pack(side=LEFT)
        ttk.Button(key_frame, text="Generate Key Pair", command=self._generate_key_pair).pack(side=LEFT, padx=5)

        password_frame = Frame(parent)
        password_frame.pack(fill=X, pady=5)
        Label(password_frame, text="Password:").pack(side=LEFT)
        ttk.Entry(password_frame, textvariable=self.password_var, width=30, show="*").pack(side=LEFT, padx=5)

        output_frame = Frame(parent)
        output_frame.pack(fill=X, pady=5)
        Label(output_frame, text="Output image:").pack(side=LEFT)
        ttk.Entry(output_frame, textvariable=self.output_image_path, width=45).pack(side=LEFT, padx=5)
        ttk.Button(output_frame, text="Browse", command=self._select_output_path).pack(side=LEFT)

        action_frame = Frame(parent)
        action_frame.pack(fill=X, pady=10)
        self.encode_progress = ttk.Progressbar(action_frame, maximum=100)
        self.encode_progress.pack(fill=X, padx=5, pady=5)
        ttk.Button(action_frame, text="Embed Message", command=self._start_encoding).pack()

    def _build_decode_tab(self, parent: Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)

        top_frame = Frame(parent)
        top_frame.pack(fill=X, pady=5)
        Label(top_frame, text="Stego image:").pack(side=LEFT)
        ttk.Entry(top_frame, textvariable=self.decode_image_path, width=50).pack(side=LEFT, padx=5)
        ttk.Button(top_frame, text="Browse", command=self._select_decode_image).pack(side=LEFT)

        preview_frame = Frame(parent)
        preview_frame.pack(fill=X, pady=5)
        Label(preview_frame, text="Preview:").pack(anchor="w")
        self.decode_canvas = Canvas(preview_frame, width=320, height=240, bg="#f0f0f0")
        self.decode_canvas.pack()

        key_frame = Frame(parent)
        key_frame.pack(fill=X, pady=5)
        Label(key_frame, text="RSA private key:").pack(side=LEFT)
        ttk.Entry(key_frame, textvariable=self.private_key_path, width=45).pack(side=LEFT, padx=5)
        ttk.Button(key_frame, text="Browse", command=self._select_private_key).pack(side=LEFT)

        password_frame = Frame(parent)
        password_frame.pack(fill=X, pady=5)
        Label(password_frame, text="Password:").pack(side=LEFT)
        ttk.Entry(password_frame, textvariable=self.decode_password_var, width=30, show="*").pack(side=LEFT, padx=5)

        result_frame = Frame(parent)
        result_frame.pack(fill=BOTH, expand=True, pady=5)
        Label(result_frame, text="Decoded message:").pack(anchor="w")
        self.decoded_text = Text(result_frame, height=8, wrap="word")
        self.decoded_text.pack(fill=BOTH, expand=True)

        action_frame = Frame(parent)
        action_frame.pack(fill=X, pady=10)
        self.decode_progress = ttk.Progressbar(action_frame, maximum=100)
        self.decode_progress.pack(fill=X, padx=5, pady=5)
        ttk.Button(action_frame, text="Extract Message", command=self._start_decoding).pack()

    # ------------------------------------------------------------------
    # File selection helpers
    # ------------------------------------------------------------------
    def _select_encode_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Select cover image",
            filetypes=[("Image files", "*.png *.bmp *.jpg *.jpeg"), ("All files", "*.*")],
        )
        if path:
            self.encode_image_path.set(path)
            self._update_preview(path, self.encode_canvas, "encode")

    def _select_decode_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Select stego image",
            filetypes=[("Image files", "*.png *.bmp *.jpg *.jpeg"), ("All files", "*.*")],
        )
        if path:
            self.decode_image_path.set(path)
            self._update_preview(path, self.decode_canvas, "decode")

    def _select_public_key(self) -> None:
        path = filedialog.askopenfilename(title="Select RSA public key", filetypes=[("PEM files", "*.pem"), ("All", "*.*")])
        if path:
            self.public_key_path.set(path)

    def _select_private_key(self) -> None:
        path = filedialog.askopenfilename(title="Select RSA private key", filetypes=[("PEM files", "*.pem"), ("All", "*.*")])
        if path:
            self.private_key_path.set(path)

    def _select_output_path(self) -> None:
        initial = self._default_output_name()
        path = filedialog.asksaveasfilename(
            title="Save stego image",
            defaultextension=".png",
            initialfile=initial,
            filetypes=[("PNG image", "*.png"), ("Bitmap", "*.bmp")],
        )
        if path:
            self.output_image_path.set(path)

    def _generate_key_pair(self) -> None:
        directory = filedialog.askdirectory(title="Select directory to store keys")
        if not directory:
            return

        try:
            pair = crypto_utils.generate_rsa_keypair()
        except Exception as exc:  # pragma: no cover - GUI feedback
            messagebox.showerror("Key generation failed", str(exc))
            return

        private_path = os.path.join(directory, "steganography_private.pem")
        public_path = os.path.join(directory, "steganography_public.pem")
        try:
            crypto_utils.save_private_key(pair.private_key, private_path)
            crypto_utils.save_public_key(pair.public_key, public_path)
        except OSError as exc:
            messagebox.showerror("Key generation failed", f"Unable to save key files: {exc}")
            return

        self.private_key_path.set(private_path)
        self.public_key_path.set(public_path)
        messagebox.showinfo("Keys generated", f"Saved private key to:\n{private_path}\n\nSaved public key to:\n{public_path}")

    def _default_output_name(self) -> str:
        source = Path(self.encode_image_path.get())
        if not source.exists():
            return "stego_image.png"
        return f"{source.stem}_stego{source.suffix or '.png'}"

    # ------------------------------------------------------------------
    # Preview helper
    # ------------------------------------------------------------------
    def _update_preview(self, path: str, canvas: Canvas, target: str) -> None:
        try:
            image = Image.open(path)
            image.thumbnail((320, 240))
            photo = ImageTk.PhotoImage(image)
        except Exception as exc:  # pragma: no cover - GUI feedback
            messagebox.showerror("Preview error", f"Unable to load image: {exc}")
            return

        canvas.delete("all")
        canvas.create_image(160, 120, image=photo)
        if target == "encode":
            self.encode_preview = photo
        else:
            self.decode_preview = photo

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------
    def _start_encoding(self) -> None:
        thread = threading.Thread(target=self._encode_worker, daemon=True)
        thread.start()

    def _encode_worker(self) -> None:
        self._set_progress(self.encode_progress, 0.0)
        try:
            image_path = self.encode_image_path.get()
            output_path = self.output_image_path.get()
            password = self.password_var.get()
            message = self.message_text.get("1.0", END).strip()
            public_key_path = self.public_key_path.get()

            if not image_path or not os.path.exists(image_path):
                raise ValueError("A valid cover image must be selected")
            if not output_path:
                raise ValueError("Please provide a destination for the stego image")
            suffix = Path(output_path).suffix.lower()
            if suffix in {".jpg", ".jpeg"}:
                raise ValueError(
                    "JPEG output cannot safely store embedded data. Choose a PNG or BMP file instead."
                )
            if not password:
                raise ValueError("Password is required for embedding")
            if not message:
                raise ValueError("Secret message cannot be empty")
            if not public_key_path or not os.path.exists(public_key_path):
                raise ValueError("A valid RSA public key must be supplied")

            self._set_progress(self.encode_progress, 10.0)
            public_key = crypto_utils.load_public_key(public_key_path)
            encrypted = crypto_utils.encrypt_message(message, public_key)
            md5_digest = crypto_utils.compute_md5(message)
            self._set_progress(self.encode_progress, 25.0)
            payload = build_payload(encrypted, md5_digest, password)
            self._set_progress(self.encode_progress, 40.0)
            embed_payload(
                image_path,
                payload,
                output_path,
                progress=lambda value: self._set_progress(self.encode_progress, value),
            )
            self._set_progress(self.encode_progress, 100.0)
            self._notify_info("Success", "Message embedded successfully")
        except Exception as exc:  # pragma: no cover - GUI feedback
            self._notify_error("Encoding failed", str(exc))
        finally:
            self.root.after(0, lambda: self.encode_progress.config(value=0))

    # ------------------------------------------------------------------
    # Decoding
    # ------------------------------------------------------------------
    def _start_decoding(self) -> None:
        thread = threading.Thread(target=self._decode_worker, daemon=True)
        thread.start()

    def _decode_worker(self) -> None:
        self._set_progress(self.decode_progress, 0.0)
        try:
            image_path = self.decode_image_path.get()
            private_key_path = self.private_key_path.get()
            password = self.decode_password_var.get()

            if not image_path or not os.path.exists(image_path):
                raise ValueError("A valid stego image must be selected")
            if not private_key_path or not os.path.exists(private_key_path):
                raise ValueError("A valid RSA private key must be supplied")
            if not password:
                raise ValueError("Password is required to decode the message")

            self._set_progress(self.decode_progress, 20.0)
            payload = extract_payload(
                image_path, progress=lambda value: self._set_progress(self.decode_progress, value)
            )
            encrypted, md5_digest = parse_payload(payload, password)
            private_key = crypto_utils.load_private_key(private_key_path)
            plaintext = crypto_utils.decrypt_message(encrypted, private_key)

            self._set_progress(self.decode_progress, 80.0)

            if crypto_utils.compute_md5(plaintext) != md5_digest:
                raise ValueError("Integrity check failed: MD5 digest mismatch")

            self._set_progress(self.decode_progress, 100.0)
            self._show_decoded_message(plaintext)
            self._notify_info("Success", "Message decoded successfully")
        except PermissionError as exc:  # pragma: no cover - GUI feedback
            self._notify_error("Access denied", str(exc))
        except ValueError as exc:  # pragma: no cover - GUI feedback
            message = str(exc)
            if "Steganography Messenger data" in message:
                message += (
                    "\n\nThe image may have been saved using JPEG compression, "
                    "which removes embedded bits. Use the original PNG/BMP stego image."
                )
            self._notify_error("Decoding failed", message)
        except Exception as exc:  # pragma: no cover - GUI feedback
            self._notify_error("Decoding failed", str(exc))
        finally:
            self.root.after(0, lambda: self.decode_progress.config(value=0))

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------
    def _set_progress(self, widget: ttk.Progressbar, value: float) -> None:
        self.root.after(0, lambda: widget.config(value=value))

    def _notify_error(self, title: str, message: str) -> None:
        self.root.after(0, lambda: messagebox.showerror(title, message))

    def _notify_info(self, title: str, message: str) -> None:
        self.root.after(0, lambda: messagebox.showinfo(title, message))

    def _show_decoded_message(self, message: str) -> None:
        def update() -> None:
            self.decoded_text.delete("1.0", END)
            self.decoded_text.insert(END, message)

        self.root.after(0, update)


def launch_app() -> None:
    root = Tk()
    SteganographyMessengerApp(root)
    root.mainloop()


__all__ = ["SteganographyMessengerApp", "launch_app"]