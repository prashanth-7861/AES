#AES Round Implementation in Python
This project is a hands‑on implementation of a single AES encryption round in Python, built to study how real block ciphers behave at the byte and bit level rather than treating AES as a black box.
​

The code walks a 128‑bit plaintext block through the core AES round transformations:

SubBytes

ShiftRows

MixColumns

AddRoundKey

and also demonstrates a simplified key‑schedule step that derives additional round keys from a 128‑bit master key
## Project structure

AES_S00443079/
├── build/                 # (optional) build artifacts
└── src/
    ├── data/
    │   ├── plaintext.txt      # 16‑byte plaintext block (e.g., "Two One Nine Two")
    │   ├── subkey_example.txt # two 128‑bit keys in hex (one per line)
    │   ├── result.txt         # final AES state after one round (auto‑generated)
    │   └── result_subkey.txt  # extra derived subkeys (auto‑generated)
    └── main.py                # AES round and key‑schedule implementation


Features
Manual AES round pipeline
Implements SubBytes, ShiftRows, MixColumns, and AddRoundKey over a 4×4 state matrix using NumPy, providing visibility into how each step transforms the state.
​

Custom key schedule demo
Implements a small key‑expansion routine that splits a 128‑bit key into words, rotates and substitutes bytes, mixes them with a round constant, and outputs the next round key material.
​

File‑driven inputs and outputs
Reads plaintext and keys from disk and writes intermediate results back to disk, mirroring how crypto is often wired into real systems and making it easier to script tests around the implementation.
​

Cross‑platform path handling (Windows / Linux)
Includes OS checks and path configuration logic so the same script can be run on different platforms with the appropriate data directory structure in place.
​

Prerequisites
Python 3.x

Required packages:
pip install numpy scipy matplotlib ipython jupyter pandas sympy nose



Getting started
1. Clone the repository
bash
git clone https://github.com/prashanth-7861/AES.git
cd AES
2. Install dependencies
pip install numpy  # minimum required
# or install all for completeness:
# pip install numpy scipy matplotlib ipython jupyter pandas sympy nose
3. Run the AES round
From the repository root:
python src/main.py


Expected output
The script prints intermediate steps and creates:

src/data/result.txt
Final 4×4 AES state matrix as a Python list of rows.

src/data/result_subkey.txt
Derived subkey words from the key‑schedule demo. 

MIT License
