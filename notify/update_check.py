"""Checks GitHub Releases for a newer version and only tells the user; it
never downloads or installs anything. Uses only the standard library. Any
problem (no internet, no release yet) is ignored quietly.
"""
import json
import urllib.error
import urllib.request

RELEASES_API_URL = 'https://api.github.com/repos/laziiiiizz/ContextGuard/releases/latest'


def _parse_version(version: str) -> tuple:
    """'v1.2.0' or '1.2.0' -> (1, 2, 0). Non-numeric parts sort as -1, so a
    genuinely malformed tag never crashes the comparison, it just never
    looks newer than a well-formed current version."""
    version = version.lstrip('vV')
    parts = []
    for part in version.split('.'):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(-1)
    return tuple(parts)


def check_for_update(current_version: str, timeout: float = 3.0) -> str | None:
    """The newest release's version if it is newer than current_version,
    otherwise None (also when offline or there is no release). Never raises."""
    try:
        request = urllib.request.Request(
            RELEASES_API_URL,
            headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'ContextGuard-update-check'},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode('utf-8'))
        latest = data.get('tag_name')
        if not latest:
            return None
        if _parse_version(latest) > _parse_version(current_version):
            return latest
        return None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, KeyError, ValueError, OSError):
        return None
