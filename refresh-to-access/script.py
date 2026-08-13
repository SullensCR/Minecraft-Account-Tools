#!/usr/bin/env python3
"""Exchange a Microsoft refresh token for a Minecraft Java session.

This follows the same Microsoft -> Xbox Live -> XSTS -> Minecraft flow used by
Localts. Credentials are accepted interactively and kept in memory only.
Only use refresh tokens belonging to an account you own or may access.
"""

from __future__ import annotations

import getpass
import re
import sys
import uuid
from dataclasses import dataclass
from typing import Any

import requests


MICROSOFT_TOKEN_URL = "https://login.live.com/oauth20_token.srf"
MICROSOFT_CLIENT_ID = "00000000402b5328"
MICROSOFT_REDIRECT_URI = "https://login.live.com/oauth20_desktop.srf"
MICROSOFT_SCOPE = "service::user.auth.xboxlive.com::MBI_SSL"

XBOX_USER_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
XBOX_RELYING_PARTY = "http://auth.xboxlive.com"
XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
MINECRAFT_RELYING_PARTY = "rp://api.minecraftservices.com/"

MINECRAFT_LOGIN_URL = (
    "https://api.minecraftservices.com/authentication/login_with_xbox"
)
MINECRAFT_ENTITLEMENTS_URL = (
    "https://api.minecraftservices.com/entitlements/license?requestId=auth"
)
MINECRAFT_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"

USER_AGENT = "Localts-compatible Minecraft refresh login/1.0"
DEFAULT_TIMEOUT = 30.0
OWNERSHIP_SOURCES = {"GAMEPASS", "PURCHASE", "MC_PURCHASE"}

XSTS_ERRORS = {
    2148916227: "The account is banned from Xbox.",
    2148916233: "The account does not have an Xbox profile yet.",
    2148916235: "Xbox Live is unavailable for the account's country or region.",
    2148916236: "The account requires adult verification on Xbox.",
    2148916237: "The account requires adult verification on Xbox.",
    2148916238: "The child account must be added to a Microsoft family by an adult.",
    2148916262: "Xbox rejected the account for an unspecified reason.",
}


class AuthenticationError(RuntimeError):
    """A safe, user-readable authentication failure."""


@dataclass(frozen=True)
class MicrosoftTokens:
    access_token: str
    refresh_token: str


@dataclass(frozen=True)
class MinecraftSession:
    username: str
    uuid: str
    access_token: str
    refresh_token: str


def _request_error(service: str, exc: requests.RequestException) -> AuthenticationError:
    if isinstance(exc, requests.Timeout):
        return AuthenticationError(f"{service} timed out. Try again.")
    return AuthenticationError(f"Could not connect to {service}. Try again.")


def _json_object(response: requests.Response, service: str) -> dict[str, Any]:
    try:
        payload = response.json()
    except (ValueError, requests.JSONDecodeError) as exc:
        raise AuthenticationError(f"{service} returned an invalid response.") from exc
    if not isinstance(payload, dict):
        raise AuthenticationError(f"{service} returned an invalid response.")
    return payload


def _check_common_status(response: requests.Response, service: str) -> None:
    if response.status_code == 429:
        raise AuthenticationError(f"{service} rate-limited the request. Try again later.")
    if response.status_code >= 500:
        raise AuthenticationError(f"{service} is temporarily unavailable.")


def _safe_error_code(value: Any) -> str | None:
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", value):
        return value
    return None


def refresh_microsoft_token(
    session: requests.Session,
    refresh_token: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> MicrosoftTokens:
    try:
        response = session.post(
            MICROSOFT_TOKEN_URL,
            data={
                "client_id": MICROSOFT_CLIENT_ID,
                "grant_type": "refresh_token",
                "redirect_uri": MICROSOFT_REDIRECT_URI,
                "refresh_token": refresh_token,
                "scope": MICROSOFT_SCOPE,
            },
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise _request_error("Microsoft authentication", exc) from exc

    _check_common_status(response, "Microsoft authentication")
    payload = _json_object(response, "Microsoft authentication")
    if response.status_code // 100 != 2 or "error" in payload:
        code = _safe_error_code(payload.get("error"))
        if code == "invalid_grant":
            raise AuthenticationError(
                "The Microsoft refresh token is invalid, expired, or revoked."
            )
        if code == "invalid_client":
            raise AuthenticationError(
                "Microsoft rejected the Minecraft launcher client configuration."
            )
        suffix = f" ({code})" if code else ""
        raise AuthenticationError(f"Microsoft rejected the refresh token{suffix}.")

    access_token = payload.get("access_token")
    replacement_refresh_token = payload.get("refresh_token")
    if not isinstance(access_token, str) or not access_token:
        raise AuthenticationError(
            "Microsoft authentication did not return an access token."
        )
    if not isinstance(replacement_refresh_token, str) or not replacement_refresh_token:
        raise AuthenticationError(
            "Microsoft authentication did not return a replacement refresh token."
        )
    return MicrosoftTokens(access_token, replacement_refresh_token)


def obtain_xbox_user_token(
    session: requests.Session,
    microsoft_access_token: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[str, str]:
    payload = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": f"t={microsoft_access_token}",
        },
        "RelyingParty": XBOX_RELYING_PARTY,
        "TokenType": "JWT",
    }
    try:
        response = session.post(
            XBOX_USER_AUTH_URL,
            json=payload,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise _request_error("Xbox Live authentication", exc) from exc

    _check_common_status(response, "Xbox Live authentication")
    if response.status_code == 401:
        raise AuthenticationError("Xbox Live rejected the Microsoft access token.")
    if response.status_code // 100 != 2:
        raise AuthenticationError(
            f"Xbox Live authentication failed (HTTP {response.status_code})."
        )
    data = _json_object(response, "Xbox Live authentication")
    try:
        token = data["Token"]
        user_hash = data["DisplayClaims"]["xui"][0]["uhs"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AuthenticationError(
            "Xbox Live authentication returned an invalid response."
        ) from exc
    if not isinstance(token, str) or not token or not isinstance(user_hash, str) or not user_hash:
        raise AuthenticationError(
            "Xbox Live authentication returned an invalid response."
        )
    return token, user_hash


def obtain_xsts_token(
    session: requests.Session,
    xbox_user_token: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    payload = {
        "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbox_user_token]},
        "RelyingParty": MINECRAFT_RELYING_PARTY,
        "TokenType": "JWT",
    }
    try:
        response = session.post(
            XSTS_AUTH_URL,
            json=payload,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise _request_error("Xbox XSTS authentication", exc) from exc

    _check_common_status(response, "Xbox XSTS authentication")
    data = _json_object(response, "Xbox XSTS authentication")
    error_code = data.get("XErr")
    if isinstance(error_code, int):
        raise AuthenticationError(
            XSTS_ERRORS.get(error_code, f"Xbox XSTS rejected the account (code {error_code}).")
        )
    if response.status_code // 100 != 2:
        raise AuthenticationError(
            f"Xbox XSTS authentication failed (HTTP {response.status_code})."
        )
    token = data.get("Token")
    if not isinstance(token, str) or not token:
        raise AuthenticationError("Xbox XSTS authentication did not return a token.")
    return token


def obtain_minecraft_access_token(
    session: requests.Session,
    xsts_token: str,
    user_hash: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    try:
        response = session.post(
            MINECRAFT_LOGIN_URL,
            json={"identityToken": f"XBL3.0 x={user_hash};{xsts_token}"},
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise _request_error("Minecraft authentication", exc) from exc

    _check_common_status(response, "Minecraft authentication")
    data = _json_object(response, "Minecraft authentication")
    if response.status_code // 100 != 2:
        code = _safe_error_code(data.get("error"))
        suffix = f" ({code})" if code else f" (HTTP {response.status_code})"
        raise AuthenticationError(f"Minecraft rejected the Xbox token{suffix}.")
    token = data.get("access_token")
    if not isinstance(token, str) or not token:
        raise AuthenticationError(
            "Minecraft authentication did not return an access token."
        )
    return token


def verify_minecraft_ownership(
    session: requests.Session,
    minecraft_access_token: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    try:
        response = session.get(
            MINECRAFT_ENTITLEMENTS_URL,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {minecraft_access_token}",
                "User-Agent": USER_AGENT,
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise _request_error("Minecraft ownership verification", exc) from exc

    _check_common_status(response, "Minecraft ownership verification")
    if response.status_code != 200:
        raise AuthenticationError(
            f"Minecraft ownership verification failed (HTTP {response.status_code})."
        )
    data = _json_object(response, "Minecraft ownership verification")
    items = data.get("items")
    if not isinstance(items, list):
        raise AuthenticationError(
            "Minecraft ownership verification returned an invalid response."
        )
    owns_minecraft = any(
        isinstance(item, dict)
        and isinstance(item.get("name"), str)
        and "minecraft" in item["name"].lower()
        and item.get("source") in OWNERSHIP_SOURCES
        for item in items
    )
    if not owns_minecraft:
        raise AuthenticationError("The account does not own Minecraft Java Edition.")


def obtain_minecraft_profile(
    session: requests.Session,
    minecraft_access_token: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[str, str]:
    try:
        response = session.get(
            MINECRAFT_PROFILE_URL,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {minecraft_access_token}",
                "User-Agent": USER_AGENT,
            },
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise _request_error("Minecraft profile lookup", exc) from exc

    _check_common_status(response, "Minecraft profile lookup")
    if response.status_code in (400, 404):
        raise AuthenticationError(
            "The Minecraft profile was not found; its username may not be set."
        )
    if response.status_code != 200:
        raise AuthenticationError(
            f"Minecraft profile lookup failed (HTTP {response.status_code})."
        )
    data = _json_object(response, "Minecraft profile lookup")
    username = data.get("name")
    profile_id = data.get("id")
    if not isinstance(username, str) or not username or not isinstance(profile_id, str):
        raise AuthenticationError("Minecraft profile lookup returned an invalid response.")
    try:
        formatted_uuid = str(uuid.UUID(profile_id))
    except (ValueError, AttributeError) as exc:
        raise AuthenticationError("Minecraft returned an invalid profile UUID.") from exc
    return username, formatted_uuid


def authenticate(
    refresh_token: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
) -> MinecraftSession:
    if not refresh_token or not refresh_token.strip():
        raise AuthenticationError("The refresh token cannot be empty.")

    owned_session = session is None
    web = session or requests.Session()
    try:
        microsoft = refresh_microsoft_token(web, refresh_token.strip(), timeout=timeout)
        xbox_token, user_hash = obtain_xbox_user_token(
            web, microsoft.access_token, timeout=timeout
        )
        xsts_token = obtain_xsts_token(web, xbox_token, timeout=timeout)
        minecraft_token = obtain_minecraft_access_token(
            web, xsts_token, user_hash, timeout=timeout
        )
        verify_minecraft_ownership(web, minecraft_token, timeout=timeout)
        username, profile_uuid = obtain_minecraft_profile(
            web, minecraft_token, timeout=timeout
        )
        return MinecraftSession(
            username=username,
            uuid=profile_uuid,
            access_token=minecraft_token,
            refresh_token=microsoft.refresh_token,
        )
    finally:
        if owned_session:
            web.close()


def main() -> int:
    try:
        refresh_token = getpass.getpass("Microsoft refresh token: ").strip()
        result = authenticate(refresh_token)
        print("\nAuthentication successful.")
        print(f"Minecraft username: {result.username}")
        print(f"Minecraft UUID: {result.uuid}")
        print(f"Minecraft access token: {result.access_token}")
        print(f"Replacement Microsoft refresh token: {result.refresh_token}")
        return 0
    except AuthenticationError as exc:
        print(f"\nAuthentication failed: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
