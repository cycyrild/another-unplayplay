import logging
import time
from pathlib import Path

from unplayplay import KeyEmu

logging.basicConfig(level=getattr(logging, "DEBUG"), format="%(levelname)s: %(message)s")

# obfuscated_key linked to the playplay token

TEST_VECTORS = [
    (
        # spotify:track:69kOkLUCkxIZYexIgSG8rq (ogg-vorbis-160)
        "2f43127d80edc9cd9f12f441e1cb7904b680f9da",  # file_id
        "66e403d94fd53b18fc4db5ae4238bffe",  # obfuscated_key
        "a503a84c1dc9271460cc13f142e0bae2",  # aes_key
    ),
    (
        "1a8e5b04837957617162724232b0c96922222447",  # file_id
        "bb6e2e06776e8ca8db5398bf81eca05c",  # obfuscated_key
        "c3206271b4c70fff8e4ac3993c4dae8a",  # aes_key
    ),
    (
        "cf1bd197a6f5d613fc856bd689e43c0f4069b800",
        "30b344d1cb6eff2ece1a8e0d8fa79113",
        "8d86fb522c00729f35b34d60b165b922",
    ),
    (
        "71df45edb4748a8b1bd4126ded06063674745182",
        "53b5c6772a5498e5056ac5692ae52226",
        "0fd3998b706247b3474b2d3cf6d8e31f",
    ),
    (
        "894813d0a3113c97ab601b0f65afb9543d96ec32",
        "b512a0031f084e375eb3fd3bb61577c3",
        "4d442c155f9a95258f613a89be957be9",
    ),
]


def test_keyemu():
    start = time.perf_counter()
    key_emu = KeyEmu(Path("Spotify.dll"))
    elapsed = time.perf_counter() - start
    print(f"KeyEmu initialized in {elapsed * 1000:.2f} ms")

    for file_id, obfuscated_key, expected_key in TEST_VECTORS:
        print(f"Testing file_id={file_id}")
        start = time.perf_counter()
        decrypted = key_emu.get_aes_key(bytes.fromhex(obfuscated_key)).hex()
        elapsed = time.perf_counter() - start

        # fmt: off
        assert decrypted == expected_key,   f"Mismatch\n" \
                                            f"file_id={file_id}\n" \
                                            f"expected={expected_key}\n" \
                                            f"got={decrypted}"
        # fmt: on
        print(f"{file_id[:8]}... OK ({elapsed * 1000:.2f} ms)")


if __name__ == "__main__":
    test_keyemu()
