"""Per-request API-key injection for the Crimson Crawler client.

The generated client's own mechanism is ``auth_header_name`` + ``token``, which
writes the key into the persistent header dict that ``httpx`` then keeps on its
``Client``/``AsyncClient``. That works, but it leaves the credential somewhere a
caller can reach and print: ``httpx.Headers.__repr__`` redacts only the names in
``httpx._models.SENSITIVE_HEADERS`` (``authorization`` and
``proxy-authorization``), and our header is ``apikey``. So
``repr(client.api.get_async_httpx_client().headers)`` disclosed the live key —
one attribute access from the documented ``client.api`` escape hatch, and the
kind of thing that lands in a debug print or a bug report.

Injecting the header per request instead keeps ``client.headers`` clean while
every request still carries the key. ``codegen.py`` rewrites the two generated
accessors to pass ``auth=ApiKeyAuth(...)`` rather than mutating ``_headers``; see
its ``_HEADER_AUTH_REWRITES``. Nothing else changes — one ``httpx.Auth`` instance
serves the sync and async clients, the ``client.api`` escape hatch, and the four
Platform namespaces, because they all share the client it is attached to.

The TypeScript SDK carries the same guarantee through its own ``src/_auth.ts``;
the two move together, so a change to how the credential is stored or printed
lands on both surfaces or neither.
"""

from __future__ import annotations

from typing import Generator

import httpx

__all__ = ["ApiKeyAuth"]


class _RedactedHeaders(httpx.Headers):
    """``httpx.Headers`` that never renders one named header's value.

    ``httpx`` redacts only the names in ``httpx._models.SENSITIVE_HEADERS``
    (``authorization``, ``proxy-authorization``). Ours is ``apikey``, so every
    container that renders headers discloses it — the client's own headers, and
    the request object httpx attaches to a transport error. Extending httpx's
    module-level set would fix all of them at once, but a library has no business
    changing how an unrelated dependency prints *its* headers process-wide, so the
    redaction is scoped to the requests we authenticate.
    """

    def __init__(self, headers: httpx.Headers, redacted: str) -> None:
        super().__init__(headers)
        self._redacted = redacted.lower()

    def __repr__(self) -> str:
        shown = {key: ("[secure]" if key.lower() == self._redacted else value) for key, value in self.multi_items()}
        return f"{httpx.Headers.__name__}({shown!r})"


class ApiKeyAuth(httpx.Auth):
    """Attach the API-key header to requests for one origin.

    ``__slots__`` keeps the value out of an instance ``__dict__``, and
    ``__repr__`` names only the header, so neither ``repr()`` nor a traceback
    rendering locals discloses the key. Reading ``_value`` still works for
    anyone who goes looking — the goal is to stop *accidental* disclosure, not
    to pretend the process cannot see its own credential.

    The key is attached **only** to the configured origin, because the header
    name ``apikey`` sits outside two separate httpx protections that are keyed on
    ``Authorization``: redaction in ``httpx.Headers.__repr__`` (handled above)
    and stripping on a cross-origin redirect.

    Be precise about what this scoping does and does not cover, because the two
    look alike and only one is closed here:

    * **Covered:** the ``client.api`` escape hatch is public, so a caller can
      hand its httpx client an absolute URL for another host
      (``get_async_httpx_client().get("https://elsewhere/...")``). Without
      scoping that request carried the key. Verified.
    * **Not covered:** redirect inheritance. httpx builds a redirect request by
      copying the previous request's headers and strips only ``Authorization``,
      and ``auth_flow`` does not re-run per redirect — so scoping here cannot
      remove an inherited ``apikey``. What actually protects us is
      ``follow_redirects=False`` on the shipped client. Do not turn that on
      without adding an event hook or transport that strips the header when the
      origin changes.

    Matches the documented contract in ``CLIENTS.md``: "the `apikey` header is
    sent to that origin".
    """

    __slots__ = ("_header_name", "_value", "_origin")

    def __init__(self, header_name: str, prefix: str, token: str, base_url: httpx.URL | str) -> None:
        self._header_name = header_name
        self._value = f"{prefix} {token}" if prefix else token
        url = base_url if isinstance(base_url, httpx.URL) else httpx.URL(base_url)
        self._origin = (url.scheme, url.host, url.port)

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if (request.url.scheme, request.url.host, request.url.port) == self._origin:
            request.headers[self._header_name] = self._value
            # The outgoing request object outlives this call: httpx attaches it to
            # any transport failure as ``exc.request``, so a caller who logs
            # ``exc.request.headers`` — or an APM agent that captures request
            # headers automatically — would print the key. Swapping in a
            # redacting container is what stops that, and it has to happen here
            # because this is the only point that knows which header is secret.
            request.headers = _RedactedHeaders(request.headers, self._header_name)
        yield request

    def __repr__(self) -> str:
        return f"{type(self).__name__}(header_name={self._header_name!r})"
