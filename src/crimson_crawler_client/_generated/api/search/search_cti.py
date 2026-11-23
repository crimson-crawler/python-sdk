from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.search_cti_request import SearchCTIRequest
from ...models.search_cti_response import SearchCTIResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: SearchCTIRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/search/cti",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | SearchCTIResponse | None:
    if response.status_code == 200:
        response_200 = SearchCTIResponse.from_dict(response.json())

        return response_200

    if response.status_code == 401:
        response_401 = cast(Any, None)
        return response_401

    if response.status_code == 422:
        response_422 = cast(Any, None)
        return response_422

    if response.status_code == 429:
        response_429 = cast(Any, None)
        return response_429

    if response.status_code == 500:
        response_500 = cast(Any, None)
        return response_500

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | SearchCTIResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchCTIRequest,
) -> Response[Any | SearchCTIResponse]:
    """Search Threat Intelligence

     Search across multiple threat intelligence knowledge bases simultaneously.

    Searches the knowledge bases selected in `sources`, including ATT&CK, CWE, CAPEC, ATLAS,
    DISARM, F3, CLOAK, location, and sector records. Each result has a canonical `_source` label.
    Use `types` to restrict compatible object types within the selected sources.

    **Sources**

    - `attack` — ATT&CK Enterprise objects
    - `attack-enterprise` — ATT&CK Enterprise objects
    - `attack-ics` — ATT&CK ICS objects
    - `attack-mobile` — ATT&CK Mobile objects
    - `cwe` — CWE weaknesses
    - `capec` — CAPEC attack patterns
    - `atlas` — MITRE ATLAS adversarial ML techniques
    - `disarm` — DISARM influence-operation techniques
    - `f3` — MITRE Fight Fraud Framework (F3) financial-crime techniques
    - `cloak` — CLOAK concealment layers for online anonymity
    - `location` — geographic threat-landscape entries
    - `sector` — industry-sector threat profiles

    An ATT&CK matrix source is not techniques-only: the same `attack` search also returns Analytics
    (`AN####`, e.g. "Analytic 0292") and tactic rows, and neither belongs to a `types` value the
    filter accepts, so they cannot be excluded. Filter on the row's own id prefix (or on
    `_source` + the presence of `technique_id`) if you need techniques alone.

    **Type filters**

    - `attack-pattern` — ATT&CK techniques and CAPEC patterns
    - `intrusion-set` — threat actor groups
    - `malware` — malware families
    - `tool` — adversary tooling
    - `campaign` — threat campaigns
    - `weakness` — CWE weaknesses
    - `course-of-action` — mitigations and countermeasures

    Each result is tagged with its knowledge base in `_source`. Results arrive in the knowledge base's
    own ranking order; no relevance score is attached. The former `relevance_score` was a function
    of the row's position **on its page** — 1.0 for the first row of every page, 0.5 for the last, so
    page 2's worst row could outrank page 1's best and tightening `limit` inflated the top rows
    (measured 2026-09-13: T1558.002 read 0.60 / 0.80 / 0.90 at `limit` 5 / 10 / 20, and the first row
    of pages 1, 2 and 3 all read 1.0). Removed rather than left as a rank dressed up as a similarity.
    The `errors` array reports any partial failures.

    Args:
        body (SearchCTIRequest): Search across multiple threat intelligence knowledge bases
            simultaneously.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchCTIResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = client.get_httpx_client().request(
        **kwargs,
    )

    return _build_response(client=client, response=response)


def sync(
    *,
    client: AuthenticatedClient,
    body: SearchCTIRequest,
) -> Any | SearchCTIResponse | None:
    """Search Threat Intelligence

     Search across multiple threat intelligence knowledge bases simultaneously.

    Searches the knowledge bases selected in `sources`, including ATT&CK, CWE, CAPEC, ATLAS,
    DISARM, F3, CLOAK, location, and sector records. Each result has a canonical `_source` label.
    Use `types` to restrict compatible object types within the selected sources.

    **Sources**

    - `attack` — ATT&CK Enterprise objects
    - `attack-enterprise` — ATT&CK Enterprise objects
    - `attack-ics` — ATT&CK ICS objects
    - `attack-mobile` — ATT&CK Mobile objects
    - `cwe` — CWE weaknesses
    - `capec` — CAPEC attack patterns
    - `atlas` — MITRE ATLAS adversarial ML techniques
    - `disarm` — DISARM influence-operation techniques
    - `f3` — MITRE Fight Fraud Framework (F3) financial-crime techniques
    - `cloak` — CLOAK concealment layers for online anonymity
    - `location` — geographic threat-landscape entries
    - `sector` — industry-sector threat profiles

    An ATT&CK matrix source is not techniques-only: the same `attack` search also returns Analytics
    (`AN####`, e.g. "Analytic 0292") and tactic rows, and neither belongs to a `types` value the
    filter accepts, so they cannot be excluded. Filter on the row's own id prefix (or on
    `_source` + the presence of `technique_id`) if you need techniques alone.

    **Type filters**

    - `attack-pattern` — ATT&CK techniques and CAPEC patterns
    - `intrusion-set` — threat actor groups
    - `malware` — malware families
    - `tool` — adversary tooling
    - `campaign` — threat campaigns
    - `weakness` — CWE weaknesses
    - `course-of-action` — mitigations and countermeasures

    Each result is tagged with its knowledge base in `_source`. Results arrive in the knowledge base's
    own ranking order; no relevance score is attached. The former `relevance_score` was a function
    of the row's position **on its page** — 1.0 for the first row of every page, 0.5 for the last, so
    page 2's worst row could outrank page 1's best and tightening `limit` inflated the top rows
    (measured 2026-09-13: T1558.002 read 0.60 / 0.80 / 0.90 at `limit` 5 / 10 / 20, and the first row
    of pages 1, 2 and 3 all read 1.0). Removed rather than left as a rank dressed up as a similarity.
    The `errors` array reports any partial failures.

    Args:
        body (SearchCTIRequest): Search across multiple threat intelligence knowledge bases
            simultaneously.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchCTIResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchCTIRequest,
) -> Response[Any | SearchCTIResponse]:
    """Search Threat Intelligence

     Search across multiple threat intelligence knowledge bases simultaneously.

    Searches the knowledge bases selected in `sources`, including ATT&CK, CWE, CAPEC, ATLAS,
    DISARM, F3, CLOAK, location, and sector records. Each result has a canonical `_source` label.
    Use `types` to restrict compatible object types within the selected sources.

    **Sources**

    - `attack` — ATT&CK Enterprise objects
    - `attack-enterprise` — ATT&CK Enterprise objects
    - `attack-ics` — ATT&CK ICS objects
    - `attack-mobile` — ATT&CK Mobile objects
    - `cwe` — CWE weaknesses
    - `capec` — CAPEC attack patterns
    - `atlas` — MITRE ATLAS adversarial ML techniques
    - `disarm` — DISARM influence-operation techniques
    - `f3` — MITRE Fight Fraud Framework (F3) financial-crime techniques
    - `cloak` — CLOAK concealment layers for online anonymity
    - `location` — geographic threat-landscape entries
    - `sector` — industry-sector threat profiles

    An ATT&CK matrix source is not techniques-only: the same `attack` search also returns Analytics
    (`AN####`, e.g. "Analytic 0292") and tactic rows, and neither belongs to a `types` value the
    filter accepts, so they cannot be excluded. Filter on the row's own id prefix (or on
    `_source` + the presence of `technique_id`) if you need techniques alone.

    **Type filters**

    - `attack-pattern` — ATT&CK techniques and CAPEC patterns
    - `intrusion-set` — threat actor groups
    - `malware` — malware families
    - `tool` — adversary tooling
    - `campaign` — threat campaigns
    - `weakness` — CWE weaknesses
    - `course-of-action` — mitigations and countermeasures

    Each result is tagged with its knowledge base in `_source`. Results arrive in the knowledge base's
    own ranking order; no relevance score is attached. The former `relevance_score` was a function
    of the row's position **on its page** — 1.0 for the first row of every page, 0.5 for the last, so
    page 2's worst row could outrank page 1's best and tightening `limit` inflated the top rows
    (measured 2026-09-13: T1558.002 read 0.60 / 0.80 / 0.90 at `limit` 5 / 10 / 20, and the first row
    of pages 1, 2 and 3 all read 1.0). Removed rather than left as a rank dressed up as a similarity.
    The `errors` array reports any partial failures.

    Args:
        body (SearchCTIRequest): Search across multiple threat intelligence knowledge bases
            simultaneously.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchCTIResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SearchCTIRequest,
) -> Any | SearchCTIResponse | None:
    """Search Threat Intelligence

     Search across multiple threat intelligence knowledge bases simultaneously.

    Searches the knowledge bases selected in `sources`, including ATT&CK, CWE, CAPEC, ATLAS,
    DISARM, F3, CLOAK, location, and sector records. Each result has a canonical `_source` label.
    Use `types` to restrict compatible object types within the selected sources.

    **Sources**

    - `attack` — ATT&CK Enterprise objects
    - `attack-enterprise` — ATT&CK Enterprise objects
    - `attack-ics` — ATT&CK ICS objects
    - `attack-mobile` — ATT&CK Mobile objects
    - `cwe` — CWE weaknesses
    - `capec` — CAPEC attack patterns
    - `atlas` — MITRE ATLAS adversarial ML techniques
    - `disarm` — DISARM influence-operation techniques
    - `f3` — MITRE Fight Fraud Framework (F3) financial-crime techniques
    - `cloak` — CLOAK concealment layers for online anonymity
    - `location` — geographic threat-landscape entries
    - `sector` — industry-sector threat profiles

    An ATT&CK matrix source is not techniques-only: the same `attack` search also returns Analytics
    (`AN####`, e.g. "Analytic 0292") and tactic rows, and neither belongs to a `types` value the
    filter accepts, so they cannot be excluded. Filter on the row's own id prefix (or on
    `_source` + the presence of `technique_id`) if you need techniques alone.

    **Type filters**

    - `attack-pattern` — ATT&CK techniques and CAPEC patterns
    - `intrusion-set` — threat actor groups
    - `malware` — malware families
    - `tool` — adversary tooling
    - `campaign` — threat campaigns
    - `weakness` — CWE weaknesses
    - `course-of-action` — mitigations and countermeasures

    Each result is tagged with its knowledge base in `_source`. Results arrive in the knowledge base's
    own ranking order; no relevance score is attached. The former `relevance_score` was a function
    of the row's position **on its page** — 1.0 for the first row of every page, 0.5 for the last, so
    page 2's worst row could outrank page 1's best and tightening `limit` inflated the top rows
    (measured 2026-09-13: T1558.002 read 0.60 / 0.80 / 0.90 at `limit` 5 / 10 / 20, and the first row
    of pages 1, 2 and 3 all read 1.0). Removed rather than left as a rank dressed up as a similarity.
    The `errors` array reports any partial failures.

    Args:
        body (SearchCTIRequest): Search across multiple threat intelligence knowledge bases
            simultaneously.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchCTIResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
