AES Round Implementation in Python
This project is a hands‑on implementation of a single AES encryption round in Python, built to study how real block ciphers behave at the byte and bit level rather than treating AES as a black box.
​

The code walks a 128‑bit plaintext block through the core AES round transformations:

SubBytes

ShiftRows

MixColumns

AddRoundKey

and also demonstrates a simplified key‑schedule step that derives additional round keys from a 128‑bit master key.


AES_S00443079/
├── build/                 # (optional) build artifacts
├── src/
│   └── main.py            # AES round and key‑schedule implementation
    ├── data/
│              ├── plaintext.txt      # 16‑byte plaintext block (e.g., "Two One Nine Two")
│              ├── subkey_example.txt # two 128‑bit keys in hex (one per line)
│              ├── result.txt         # final AES state after one round (auto‑generated)
│              └── result_subkey.txt  # extra derived subkeys (auto‑generated)
