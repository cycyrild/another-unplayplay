# Playplay keygen

> [!IMPORTANT]
> ### **SPOTIFY HAS BANNED THE CLIENT VERSION USED BY THIS PROJECT, SO IT NO LONGER WORKS.**

#

This repository contains the Playplay keygen previously part of `spotify-dl-cli`.

Original project: \
https://github.com/cycyrild/spotify-dl-cli

It provides an AES decryption key generator for Spotify content by emulating the Playplay runtime.

```python
from pathlib import Path
from unplayplay import KeyEmu

# Initialize with a compatible Spotify binary
emu = KeyEmu(Path("Spotify.dll"))

# Obfuscated key
obfuscated_key = bytes.fromhex("0694259138997536f3ddcf2be2855c8a")

# Extract AES key
aes_key = emu.get_aes_key(obfuscated_key)

print(aes_key.hex())
```
The Spotify binary must match the expected version/hash
