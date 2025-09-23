# Identifying-Cryptographic-Function-in-Blockchain

Dependencies

Python 3.10–3.12

OS: Windows / macOS / Linux

Tk (bundled with most Python installers)

libmagic (macOS/Linux only; see below)

Environment

Create a .env file next to loginTest.py:

SUPABASE_URL=your-project-url
SUPABASE_ANON_KEY=your-anon-key


Install (Windows)

python -m venv .venv
.venv\Scripts\activate
pip install customtkinter supabase python-dotenv tkinterdnd2 python-magic-bin


Install (macOS)

python3 -m venv .venv
source .venv/bin/activate
brew install libmagic          # required by python-magic
pip install customtkinter supabase python-dotenv tkinterdnd2 python-magic


Install (Ubuntu/Debian Linux)

python3 -m venv .venv
source .venv/bin/activate
sudo apt-get update && sudo apt-get install -y libmagic1
pip install customtkinter supabase python-dotenv tkinterdnd2 python-magic


Run

python loginTest.py