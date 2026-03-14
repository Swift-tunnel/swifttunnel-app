#!/usr/bin/env python3

import re
import sys


SEMVER_RE = re.compile(
    r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


def semver_key(tag: str):
    match = SEMVER_RE.fullmatch(tag)
    if not match:
        return None

    major, minor, patch = (int(match.group(i)) for i in range(1, 4))
    prerelease = match.group(4)
    prerelease_key = []

    if prerelease:
        for identifier in prerelease.split("."):
            if identifier.isdigit():
                prerelease_key.append((0, int(identifier)))
            else:
                prerelease_key.append((1, identifier))

    return (major, minor, patch, 1 if prerelease is None else 0, prerelease_key)


def main() -> int:
    tags = [line.strip() for line in sys.stdin if line.strip()]
    valid_tags = [tag for tag in tags if semver_key(tag) is not None]
    if not valid_tags:
        return 0

    print(max(valid_tags, key=semver_key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
