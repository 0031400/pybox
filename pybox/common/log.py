from typing import Any


def log(tag: str, data: Any):
    if tag == "error":
        print(f"\033[31m[{tag}]\033[0m {data}")
    else:
        print(f"[{tag}] {data}")
