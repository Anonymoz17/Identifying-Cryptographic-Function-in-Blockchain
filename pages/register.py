# pages/register.py
import customtkinter as ctk
from PIL import Image, ImageDraw

from api_client_supabase import register_user as sb_register

# --- layout constants (tweak) ---
ENTRY_W = 420
ENTRY_H = 44  # ↑ was 40
RADIUS = 10
LEFT_PAD = 8
ICON_BOX = (20, 20)
ICON_GUTTER = 40
ROW_PADY = (12, 10)  # a hair more breathing room


def _make_eye_icon(opened: bool) -> Image.Image:
    """
    Draw a simple eye / eye-off icon on an identical-size transparent canvas.
    Keeping the same BOX for both states guarantees no visual shift.
    """
    w, h = ICON_BOX
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # eye outline (ellipse)
    pad = 3
    d.ellipse(
        [pad, h // 2 - 6, w - pad, h // 2 + 6], outline=(220, 220, 220, 255), width=2
    )

    # iris
    d.ellipse(
        [w // 2 - 3, h // 2 - 3, w // 2 + 3, h // 2 + 3], fill=(220, 220, 220, 255)
    )

    if not opened:
        # diagonal slash for "closed"
        d.line([pad, h - pad, w - pad, pad], fill=(220, 220, 220, 255), width=2)

    return img


class _EntryShell(ctk.CTkFrame):
    """Uniform shell so all input rows align perfectly."""

    def __init__(self, master, placeholder: str, with_right_slot: bool = False):
        super().__init__(
            master,
            fg_color=ctk.ThemeManager.theme["CTkEntry"]["fg_color"],
            corner_radius=RADIUS,
            border_width=1,
            border_color=ctk.ThemeManager.theme["CTkEntry"]["border_color"],
            width=ENTRY_W,
            height=ENTRY_H,
        )
        self.grid_propagate(False)
        self.grid_columnconfigure(0, weight=1)
        if with_right_slot:
            self.grid_columnconfigure(1, weight=0, minsize=ICON_GUTTER)

        self.entry = ctk.CTkEntry(
            self,
            placeholder_text=placeholder,
            height=ENTRY_H - 4,  # ↓ inner entry slightly shorter
            corner_radius=RADIUS,
            border_width=0,
        )
        # add a tiny vertical inset so the top arc never clips
        self.entry.grid(row=0, column=0, padx=(LEFT_PAD, 8), pady=(2, 2), sticky="nsew")


class RegisterPage(ctk.CTkFrame):
    def __init__(self, master, switch_page):
        super().__init__(master)
        self.switch_page = switch_page
        self._pw_shown = False

        # -------- container & card --------
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.place(relx=0.5, rely=0.5, anchor="center")

        card = ctk.CTkFrame(
            container, corner_radius=16, border_width=1, border_color="#374151"
        )
        card.grid(row=0, column=0, padx=16, pady=16, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            card, text="Create your CryptoScope account", font=("Segoe UI", 24, "bold")
        )
        subtitle = ctk.CTkLabel(
            card, text="Sign up to get started", font=("Segoe UI", 12)
        )
        title.grid(row=0, column=0, padx=20, pady=(20, 6), sticky="w")
        subtitle.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        # -------- aligned input shells --------
        self.full_name_shell = _EntryShell(card, "Full name")
        self.username_shell = _EntryShell(card, "Username")
        self.email_shell = _EntryShell(card, "Email")
        self.pw_shell = _EntryShell(card, "Password", with_right_slot=True)

        # even vertical spacing and consistent side margins
        self.full_name_shell.grid(row=2, column=0, padx=35, pady=ROW_PADY, sticky="w")
        self.username_shell.grid(row=3, column=0, padx=35, pady=ROW_PADY, sticky="w")
        self.email_shell.grid(row=4, column=0, padx=35, pady=ROW_PADY, sticky="w")
        self.pw_shell.grid(row=5, column=0, padx=35, pady=ROW_PADY, sticky="w")

        # shorthand entries
        self.full_name = self.full_name_shell.entry
        self.username = self.username_shell.entry
        self.email = self.email_shell.entry
        self.pw = self.pw_shell.entry
        self.pw.configure(show="•")

        # -------- eye icon (never moves) --------
        # generate icons on identical canvases
        self.eye_open_img_ctk = ctk.CTkImage(_make_eye_icon(True), size=ICON_BOX)
        self.eye_closed_img_ctk = ctk.CTkImage(_make_eye_icon(False), size=ICON_BOX)

        # label (no button padding), positioned with place() so it never influences layout
        self.eye_lbl = ctk.CTkLabel(self.pw_shell, text="", image=self.eye_open_img_ctk)
        self.eye_lbl.place(relx=1.0, rely=0.5, x=-10, y=0, anchor="e")
        self.eye_lbl.bind("<Button-1>", lambda e: self._toggle_password())
        self.eye_lbl.bind("<Enter>", lambda e: self.eye_lbl.configure(cursor="hand2"))
        self.eye_lbl.bind("<Leave>", lambda e: self.eye_lbl.configure(cursor="arrow"))

        # -------- submit (aligned with inputs) --------
        self.create_btn = ctk.CTkButton(
            card,
            text="Create account",
            height=40,
            corner_radius=10,
            width=ENTRY_W,
            command=self._do_register,
        )
        self.create_btn.grid(
            row=6, column=0, padx=35, pady=(12, 10), sticky="w"
        )  # same left/right as inputs

        # -------- divider + back link --------
        ctk.CTkFrame(card, height=1, fg_color="#1F2937").grid(
            row=7, column=0, padx=20, pady=(8, 8), sticky="ew"
        )
        ctk.CTkLabel(card, text="Already have an account?", font=("Segoe UI", 11)).grid(
            row=8, column=0, padx=20, pady=(0, 6), sticky="w"
        )

        link_row = ctk.CTkFrame(card, fg_color="transparent")
        link_row.grid(
            row=9, column=0, padx=35, pady=(0, 12), sticky="w"
        )  # align visually with inputs/button

        ctk.CTkButton(
            link_row,
            text="Back to Sign in",
            height=28,
            corner_radius=8,
            fg_color="transparent",
            hover_color="#1F2937",
            border_width=1,
            border_color="#374151",
            text_color="#E5E7EB",
            command=lambda: self.switch_page("login"),
        ).pack(side="left")

        self.status = ctk.CTkLabel(card, text="", font=("Segoe UI", 11))
        self.status.grid(row=10, column=0, padx=35, pady=(0, 16), sticky="w")

    # -------- handlers --------
    def _toggle_password(self):
        self._pw_shown = not self._pw_shown
        self.pw.configure(show="" if self._pw_shown else "•")
        # swap image only (same canvas & size) => no movement
        self.eye_lbl.configure(
            image=self.eye_closed_img_ctk if self._pw_shown else self.eye_open_img_ctk
        )

    def _set_status(self, text, error=False):
        self.status.configure(text=text, text_color=("red" if error else "#4B5563"))

    def _do_register(self):
        full_name = (self.full_name.get() or "").strip()
        username = (self.username.get() or "").strip()
        email = (self.email.get() or "").strip()
        password = self.pw.get() or ""
        if not full_name or not username or not email or not password:
            return self._set_status("Please fill in all fields.", True)

        try:
            ok, data = sb_register(
                email=email, password=password, full_name=full_name, username=username
            )
        except Exception as e:
            return self._set_status(f"Registration error: {e}", True)

        if ok:
            self._set_status("Account created. Please log in.")
            self.switch_page("login")
        else:
            self._set_status(
                data if isinstance(data, str) else "Registration failed.", True
            )

    def on_resize(self, w, h):
        pass
