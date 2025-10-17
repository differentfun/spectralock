# SpectraLock

Hide and recover text (URLs or generic messages) inside an image while protecting it with a password. The script automatically uses [Zenity](https://help.gnome.org/users/zenity/stable/) dialogs when available and falls back to plain terminal prompts otherwise.

## Features
- Authenticated encryption (AES-GCM) with keys derived from the password using scrypt.
- Least-significant-bit (LSB) embedding so only a single bit per pixel channel is modified.
- PNG output uses lossless LSB embedding, while JPEG output stores the payload inside custom metadata blocks.
- Supports arbitrary UTF-8 text within the capacity offered by the image.
- Accepts PNG, JPEG/JPG, and most Pillow-supported formats as sources, keeping the chosen format for the stego image.

## Requirements
- Python ≥ 3.8
- Python packages: `cryptography`, `Pillow`
- Optional: `zenity` binary on PATH for the graphical dialogs (often packaged as `zenity` or `gnome-zenity`).

## Quick Start
1. Create a virtual environment (see `set-environment.sh`) and install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install cryptography Pillow
   ```
2. Launch the tool:
   ```bash
   python3 spectralock.py
   ```
   or simply run
   ```bash
   bash launch.sh
   ```
   which creates/activates the virtual environment automatically before starting SpectraLock.

### Encrypt and Hide Text
1. Choose **Encrypt and hide text**.
2. Pick the source image (any Pillow-supported format).
3. Enter the message you want to hide.
4. Provide and confirm the encryption password.
5. Choose where to save the output image (saved as PNG; `.png` is added automatically if omitted).

### Recover Hidden Text
1. Choose **Recover hidden text**.
2. Select the image that contains hidden data.
3. Enter the password. If it matches, the original text is displayed.

## Tips and Limitations
- Ensure the image is large enough. Each byte of encrypted data consumes 8 pixel channels, plus 32 header bits.
- Avoid any lossy transformations (JPEG re-save, aggressive resizing) after hiding the message; JPEG payloads live in metadata blocks that many editors strip away.
- Strong passwords still matter: scrypt slows down brute-force attempts but weak passwords remain vulnerable.
- In terminal mode the script uses `getpass` so passwords are not echoed to the screen.

## Development Notes
Sample files `test_input.png` and `test_output.png` may exist if you run local tests. Remove them manually when they are no longer needed:

```bash
rm test_input.png test_output.png
```

## License
SpectraLock is distributed under the terms of the GNU General Public License v3.0. See the `LICENSE` file for the full text.  
This code is supplied strictly for study and testing purposes. The authors accept no responsibility or liability for misuse, data loss, or damage arising from running SpectraLock.
