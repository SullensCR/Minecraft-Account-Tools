#!/usr/bin/env python3
"""Authenticate a Minecraft account from an exported login.live.com cookie file."""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

import requests


SISU_URL = (
    "https://sisu.xboxlive.com/connect/XboxLive/"
    "?state=login"
    "&cobrandId=8058f65d-ce06-4c30-9559-473c9275a65d"
    "&tid=896928775"
    "&ru=https%3A%2F%2Fwww.minecraft.net%2Fen-us%2Flogin"
    "&aid=1142970254"
)
MINECRAFT_LOGIN_URL = (
    "https://api.minecraftservices.com/authentication/login_with_xbox"
)
MINECRAFT_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"
RELYING_PARTY = "rp://api.minecraftservices.com/"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
ALLOWED_REDIRECT_SUFFIXES = (
    "live.com",
    "xboxlive.com",
    "minecraft.net",
    "minecraftservices.com",
)


class AuthenticationError(RuntimeError):
    """An expected, user-readable authentication failure."""


def _is_login_live_host(host: str | None) -> bool:
    host = (host or "").lower().rstrip(".")
    return host == "login.live.com" or host.endswith(".login.live.com")


def _is_allowed_redirect(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower().rstrip(".")
    return any(host == suffix or host.endswith("." + suffix) for suffix in ALLOWED_REDIRECT_SUFFIXES)


def load_login_cookies(cookie_file: Path) -> dict[str, str]:
    """Load unique login.live.com cookies from a Netscape cookie export."""
    if not cookie_file.is_file():
        raise AuthenticationError(f"Cookie file does not exist: {cookie_file}")

    cookies: dict[str, str] = {}
    try:
        lines = cookie_file.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError as exc:
        raise AuthenticationError(f"Could not read the cookie file: {exc}") from exc

    for line_number, line in enumerate(lines, start=1):
        if not line or (line.startswith("#") and not line.startswith("#HttpOnly_")):
            continue

        columns = line.split("\t", 6)
        if len(columns) != 7:
            continue

        domain = columns[0].removeprefix("#HttpOnly_").lstrip(".").lower()
        name, value = columns[5], columns[6]
        if not _is_login_live_host(domain):
            continue
        if not name:
            continue
        if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
            raise AuthenticationError(
                f"Unsafe newline found in a cookie on line {line_number}."
            )
        # Match OpenRise: keep the first cookie when a name is duplicated.
        cookies.setdefault(name, value)

    if not cookies:
        raise AuthenticationError(
            "No login.live.com cookies were found. Export cookies in Netscape "
            "(tab-separated) format while signed in to Microsoft."
        )
    return cookies


def _cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def _extract_access_token(location: str) -> str | None:
    parsed = urlsplit(location)
    for part in (parsed.query, parsed.fragment):
        for field in part.split("&"):
            name, separator, value = field.partition("=")
            # unquote() deliberately preserves literal '+' characters in Base64.
            if separator and unquote(name) == "accessToken" and value:
                return unquote(value)

    # Some redirect implementations place a query-like string after another '#'.
    match = re.search(r"(?:[?#&]|^)accessToken=([^&#]+)", location)
    return unquote(match.group(1)) if match else None


def obtain_sisu_access_token(
    session: requests.Session,
    cookies: dict[str, str],
    *,
    timeout: float,
    max_redirects: int = 8,
) -> str:
    """Follow OpenRise's manual SISU redirect flow and return accessToken."""
    url = SISU_URL
    cookie_header = _cookie_header(cookies)

    for _ in range(max_redirects + 1):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
            "User-Agent": USER_AGENT,
        }
        if _is_login_live_host(urlsplit(url).hostname):
            headers["Cookie"] = cookie_header

        try:
            response = session.get(
                url, headers=headers, allow_redirects=False, timeout=timeout
            )
        except requests.RequestException as exc:
            raise AuthenticationError(f"Microsoft sign-in request failed: {exc}") from exc

        if not 300 <= response.status_code < 400:
            if response.status_code in (401, 403):
                raise AuthenticationError(
                    "Microsoft rejected the cookies. They may be expired; export a fresh file."
                )
            raise AuthenticationError(
                f"Expected a Microsoft sign-in redirect, but received HTTP {response.status_code}."
            )

        raw_location = response.headers.get("Location")
        if not raw_location:
            raise AuthenticationError("Microsoft returned a redirect without a Location header.")
        location = urljoin(url, raw_location.replace(" ", "%20"))

        access_token = _extract_access_token(location)
        if access_token:
            return access_token
        if not _is_allowed_redirect(location):
            host = urlsplit(location).hostname or "unknown host"
            raise AuthenticationError(
                f"Stopped before sending data to an unexpected redirect host: {host}"
            )
        url = location

    raise AuthenticationError(
        f"Microsoft sign-in exceeded the safe limit of {max_redirects} redirects."
    )


def _decode_base64_json(encoded: str) -> Any:
    candidate = unquote(encoded).strip()
    padding = "=" * (-len(candidate) % 4)
    try:
        decoded = base64.urlsafe_b64decode(candidate + padding).decode("utf-8")
        return json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthenticationError(
            "Microsoft returned an accessToken in an unfamiliar format."
        ) from exc


def _credentials_in_node(node: Any) -> tuple[str, str] | None:
    if isinstance(node, dict):
        token = node.get("Token")
        claims = node.get("DisplayClaims")
        if isinstance(token, str) and isinstance(claims, dict):
            xui = claims.get("xui")
            if isinstance(xui, list) and xui and isinstance(xui[0], dict):
                uhs = xui[0].get("uhs")
                if isinstance(uhs, str) and uhs:
                    return token, uhs

        # Prefer the token explicitly issued for Minecraft services.
        if RELYING_PARTY in node:
            found = _credentials_in_node(node[RELYING_PARTY])
            if found:
                return found
        for value in node.values():
            found = _credentials_in_node(value)
            if found:
                return found

    if isinstance(node, list):
        for index, value in enumerate(node[:-1]):
            if value == RELYING_PARTY:
                found = _credentials_in_node(node[index + 1])
                if found:
                    return found
        for value in node:
            found = _credentials_in_node(value)
            if found:
                return found
    return None


def _credentials_for_relying_party(node: Any) -> tuple[str, str] | None:
    """Find credentials paired specifically with Minecraft's relying party."""
    if isinstance(node, dict):
        # SISU currently represents KeyValuePairs as {"Item1": rp, "Item2": token}.
        if node.get("Item1") == RELYING_PARTY:
            found = _credentials_in_node(node.get("Item2"))
            if found:
                return found

        # Also support a regular JSON object keyed directly by relying party.
        if RELYING_PARTY in node:
            found = _credentials_in_node(node[RELYING_PARTY])
            if found:
                return found

        for value in node.values():
            found = _credentials_for_relying_party(value)
            if found:
                return found

    if isinstance(node, list):
        # Retain support for a two-item array representation: [relyingParty, token].
        for index, value in enumerate(node[:-1]):
            if value == RELYING_PARTY:
                found = _credentials_in_node(node[index + 1])
                if found:
                    return found
        for value in node:
            found = _credentials_for_relying_party(value)
            if found:
                return found
    return None


def extract_xbox_credentials(access_token: str) -> tuple[str, str]:
    payload = _decode_base64_json(access_token)
    # Search the whole payload for the Minecraft-specific pair before accepting
    # any generic Token/DisplayClaims object. SISU commonly returns several tokens.
    credentials = _credentials_for_relying_party(payload)
    if not credentials:
        credentials = _credentials_in_node(payload)
    if not credentials:
        raise AuthenticationError(
            "The SISU token did not contain the Xbox token and user hash required by Minecraft."
        )
    return credentials


def _error_detail(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    if isinstance(payload, dict):
        for key in ("errorMessage", "error", "message", "path"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                return f"HTTP {response.status_code}: {value}"
    return f"HTTP {response.status_code}"


def login_to_minecraft(
    session: requests.Session,
    xbox_token: str,
    user_hash: str,
    *,
    timeout: float,
) -> dict[str, str]:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    try:
        login_response = session.post(
            MINECRAFT_LOGIN_URL,
            headers=headers,
            json={
                "identityToken": f"XBL3.0 x={user_hash};{xbox_token}",
                "ensureLegacyEnabled": True,
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise AuthenticationError(f"Minecraft authentication failed: {exc}") from exc

    if login_response.status_code // 100 != 2:
        raise AuthenticationError(
            "Minecraft rejected the Xbox token ("
            + _error_detail(login_response)
            + ")."
        )
    try:
        minecraft_token = login_response.json()["access_token"]
    except (ValueError, KeyError, TypeError) as exc:
        raise AuthenticationError(
            "Minecraft's login response did not include an access token."
        ) from exc

    try:
        profile_response = session.get(
            MINECRAFT_PROFILE_URL,
            headers={**headers, "Authorization": f"Bearer {minecraft_token}"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise AuthenticationError(f"Minecraft profile request failed: {exc}") from exc

    if profile_response.status_code // 100 != 2:
        raise AuthenticationError(
            "Could not load a Minecraft Java profile ("
            + _error_detail(profile_response)
            + "). The account may not own Minecraft Java Edition."
        )
    try:
        profile = profile_response.json()
        username, profile_id = profile["name"], profile["id"]
    except (ValueError, KeyError, TypeError) as exc:
        raise AuthenticationError("Minecraft returned an invalid profile response.") from exc

    return {
        "name": str(username),
        "uuid": str(profile_id),
        "access_token": str(minecraft_token),
        "refresh_token": "",
    }


def authenticate(cookie_file: Path, timeout: float = 30.0) -> dict[str, str]:
    cookies = load_login_cookies(cookie_file)
    with requests.Session() as session:
        sisu_token = obtain_sisu_access_token(
            session, cookies, timeout=timeout
        )
        xbox_token, user_hash = extract_xbox_credentials(sisu_token)
        return login_to_minecraft(
            session, xbox_token, user_hash, timeout=timeout
        )


def choose_cookie_file() -> Path:
    try:
        from tkinter import Tk, filedialog

        root = Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askopenfilename(
            title="Select login.live.com cookie file",
            filetypes=(("Text files", "*.txt"), ("All files", "*")),
        )
        root.destroy()
    except Exception as exc:
        raise AuthenticationError(
            "The file chooser could not open. Pass the cookie file path on the command line."
        ) from exc
    if not selected:
        raise AuthenticationError("No cookie file was selected.")
    return Path(selected)


def save_session(path: Path, profile: dict[str, str], *, force: bool) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(profile, output, indent=2)
            output.write("\n")
    except FileExistsError as exc:
        raise AuthenticationError(
            f"Output already exists: {path}. Use --force to replace it."
        ) from exc
    except OSError as exc:
        raise AuthenticationError(f"Could not save the session file: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Authenticate one Minecraft account using an exported login.live.com "
            "cookie file, following OpenRise's SISU flow."
        )
    )
    parser.add_argument(
        "cookie_file",
        nargs="?",
        type=Path,
        help="Netscape/tab-separated cookie file; omit to open a file chooser",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="save the Minecraft profile and access token to a private JSON file",
    )
    parser.add_argument(
        "--force", action="store_true", help="replace an existing --output file"
    )
    parser.add_argument(
        "--show-token",
        action="store_true",
        help="print the sensitive Minecraft access token to the terminal",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="network timeout in seconds (default: 30)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        print("Error: --timeout must be greater than zero.", file=sys.stderr)
        return 2

    try:
        cookie_file = args.cookie_file or choose_cookie_file()
        profile = authenticate(cookie_file.expanduser().resolve(), args.timeout)
        print("Authentication successful.")
        print(f"Minecraft name: {profile['name']}")
        print(f"Minecraft UUID: {profile['uuid']}")
        if args.show_token:
            print(f"Access token: {profile['access_token']}")
        else:
            print("Access token: hidden (use --show-token only if you truly need it)")
        if args.output:
            save_session(args.output, profile, force=args.force)
            print(f"Private session file saved to: {args.output.expanduser().resolve()}")
        return 0
    except AuthenticationError as exc:
        print(f"Authentication failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
