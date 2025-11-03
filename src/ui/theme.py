# src/ui/theme.py
"""
CryptoScope Unified Dark Theme (Brighter + Readability Update)
--------------------------------------------------------------
- Slightly lighter text and cards to reduce the "too dark" feel
- Increased font sizes for clearer hierarchy
- Calm teal accent retained for a modern, professional look
"""

# === Core Surfaces ===
BG         = "#0D1117"   # Main window background (dark navy)
CARD_BG    = "#1E2631"   # Lighter card background for better contrast
BORDER     = "#2C3540"   # Softer border to define sections without harsh lines

# === Typography Colors ===
TEXT       = "#DDE2E8"   # Brighter off-white for primary text
MUTED      = "#A2A9B3"   # Lighter secondary text for improved readability

# === Accent (Calm Teal) ===
PRIMARY    = "#2389DA"   # Primary action color (buttons, emphasis)
PRIMARY_H  = "#1A6FB8"   # Hover for primary actions

# === Outlines / Neutral Buttons ===
OUTLINE_BR = "#30363D"   # Outline border for secondary buttons/frames
OUTLINE_H  = "#2D333B"   # Hover color for outline buttons

# === Fonts (tuned for readability on dark UI) ===
TITLE_FONT   = ("Segoe UI", 32, "bold")  # Page titles
SUB_FONT     = ("Segoe UI", 13)          # Subtitles, helper text
HEADING_FONT = ("Segoe UI", 20, "bold")  # Section headings
BODY_FONT    = ("Segoe UI", 13)          # General body text

# Optional monospace for previews/logs (JSON, code, etc.)
MONO_FONT    = ("Consolas", 12)
