from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrich_cwe_request import EnrichCWERequest
from ...models.enrich_cwe_response import EnrichCWEResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: EnrichCWERequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/enrich/cwe",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichCWEResponse | None:
    if response.status_code == 200:
        response_200 = EnrichCWEResponse.from_dict(response.json())

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
) -> Response[Any | EnrichCWEResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichCWERequest,
) -> Response[Any | EnrichCWEResponse]:
    """Enrich CWE

     Enrich a weakness classification with linked attack patterns and their ATT&CK mappings.

    Provide `cwe_id` for a direct lookup (e.g. CWE-79) or `search` for discovery by name; a request
    naming neither is rejected with `422`.
    Returns the weakness with associated attack patterns and the ATT&CK techniques those patterns map
    to, connecting root cause to adversary behavior. The technique layer is resolved from this
    weakness's
    CAPEC links, so it is only as complete as those links are: a CAPEC carrying no ATT&CK mapping
    contributes none, and mitigation and detection guidance covers the techniques that do resolve —
    there is none when the linked CAPECs carry no mappings.

    **Include options**

    - `details` — CWE object with name, description, and severity
    - `capecs` — attack patterns linked to this weakness class
    - `techniques` — ATT&CK techniques linked to this weakness class
    - `tie` — technique likelihood predictions for resolved techniques
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs referencing this weakness (queried by weakness id, independent of the technique
    layer)
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated summary of the weakness and its attack implications
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    The technique-derived layers — `groups`, `software`, `campaigns`, `mitigations`, `detections`,
    `defend` and `nist_controls` — read the resolved technique set, and this endpoint resolves that
    set itself from the weakness' CAPEC links, so each one answers when asked for ALONE and publishes
    only its own section. `techniques[]` is the carrier that stays tied to the CAPEC walk rather than
    to its own token: measured 2026-09-13 on CWE-522, `techniques`=0 with `['details','techniques']`
    against `attack_patterns`=13 / `techniques`=12 with `['details','capecs','techniques']` — while a
    `['nist_controls']`-only request maps that same CAPEC-linked set instead of short-circuiting to
    `[]` (verified live 2026-10-15: CWE-522 alone → 198 controls, identical to the `capecs`-included
    request; CWE-79 resolves no technique at all, so its `nist_controls` is empty in every shape).

    Args:
        body (EnrichCWERequest): Enrich a weakness classification with linked attack patterns and
            their ATT&CK mappings.

            Techniques resolve from this weakness's CAPEC links, so the layer is only as complete as
            those
            links are: a CAPEC carrying no ATT&CK mapping contributes none, and the layers derived
            from
            techniques are empty with it. Some weaknesses carry no CAPECs at all.
            Supply at least one of `cwe_id` or `search`.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichCWEResponse]
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
    body: EnrichCWERequest,
) -> Any | EnrichCWEResponse | None:
    """Enrich CWE

     Enrich a weakness classification with linked attack patterns and their ATT&CK mappings.

    Provide `cwe_id` for a direct lookup (e.g. CWE-79) or `search` for discovery by name; a request
    naming neither is rejected with `422`.
    Returns the weakness with associated attack patterns and the ATT&CK techniques those patterns map
    to, connecting root cause to adversary behavior. The technique layer is resolved from this
    weakness's
    CAPEC links, so it is only as complete as those links are: a CAPEC carrying no ATT&CK mapping
    contributes none, and mitigation and detection guidance covers the techniques that do resolve —
    there is none when the linked CAPECs carry no mappings.

    **Include options**

    - `details` — CWE object with name, description, and severity
    - `capecs` — attack patterns linked to this weakness class
    - `techniques` — ATT&CK techniques linked to this weakness class
    - `tie` — technique likelihood predictions for resolved techniques
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs referencing this weakness (queried by weakness id, independent of the technique
    layer)
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated summary of the weakness and its attack implications
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    The technique-derived layers — `groups`, `software`, `campaigns`, `mitigations`, `detections`,
    `defend` and `nist_controls` — read the resolved technique set, and this endpoint resolves that
    set itself from the weakness' CAPEC links, so each one answers when asked for ALONE and publishes
    only its own section. `techniques[]` is the carrier that stays tied to the CAPEC walk rather than
    to its own token: measured 2026-09-13 on CWE-522, `techniques`=0 with `['details','techniques']`
    against `attack_patterns`=13 / `techniques`=12 with `['details','capecs','techniques']` — while a
    `['nist_controls']`-only request maps that same CAPEC-linked set instead of short-circuiting to
    `[]` (verified live 2026-10-15: CWE-522 alone → 198 controls, identical to the `capecs`-included
    request; CWE-79 resolves no technique at all, so its `nist_controls` is empty in every shape).

    Args:
        body (EnrichCWERequest): Enrich a weakness classification with linked attack patterns and
            their ATT&CK mappings.

            Techniques resolve from this weakness's CAPEC links, so the layer is only as complete as
            those
            links are: a CAPEC carrying no ATT&CK mapping contributes none, and the layers derived
            from
            techniques are empty with it. Some weaknesses carry no CAPECs at all.
            Supply at least one of `cwe_id` or `search`.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichCWEResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: EnrichCWERequest,
) -> Response[Any | EnrichCWEResponse]:
    """Enrich CWE

     Enrich a weakness classification with linked attack patterns and their ATT&CK mappings.

    Provide `cwe_id` for a direct lookup (e.g. CWE-79) or `search` for discovery by name; a request
    naming neither is rejected with `422`.
    Returns the weakness with associated attack patterns and the ATT&CK techniques those patterns map
    to, connecting root cause to adversary behavior. The technique layer is resolved from this
    weakness's
    CAPEC links, so it is only as complete as those links are: a CAPEC carrying no ATT&CK mapping
    contributes none, and mitigation and detection guidance covers the techniques that do resolve —
    there is none when the linked CAPECs carry no mappings.

    **Include options**

    - `details` — CWE object with name, description, and severity
    - `capecs` — attack patterns linked to this weakness class
    - `techniques` — ATT&CK techniques linked to this weakness class
    - `tie` — technique likelihood predictions for resolved techniques
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs referencing this weakness (queried by weakness id, independent of the technique
    layer)
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated summary of the weakness and its attack implications
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    The technique-derived layers — `groups`, `software`, `campaigns`, `mitigations`, `detections`,
    `defend` and `nist_controls` — read the resolved technique set, and this endpoint resolves that
    set itself from the weakness' CAPEC links, so each one answers when asked for ALONE and publishes
    only its own section. `techniques[]` is the carrier that stays tied to the CAPEC walk rather than
    to its own token: measured 2026-09-13 on CWE-522, `techniques`=0 with `['details','techniques']`
    against `attack_patterns`=13 / `techniques`=12 with `['details','capecs','techniques']` — while a
    `['nist_controls']`-only request maps that same CAPEC-linked set instead of short-circuiting to
    `[]` (verified live 2026-10-15: CWE-522 alone → 198 controls, identical to the `capecs`-included
    request; CWE-79 resolves no technique at all, so its `nist_controls` is empty in every shape).

    Args:
        body (EnrichCWERequest): Enrich a weakness classification with linked attack patterns and
            their ATT&CK mappings.

            Techniques resolve from this weakness's CAPEC links, so the layer is only as complete as
            those
            links are: a CAPEC carrying no ATT&CK mapping contributes none, and the layers derived
            from
            techniques are empty with it. Some weaknesses carry no CAPECs at all.
            Supply at least one of `cwe_id` or `search`.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichCWEResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: EnrichCWERequest,
) -> Any | EnrichCWEResponse | None:
    """Enrich CWE

     Enrich a weakness classification with linked attack patterns and their ATT&CK mappings.

    Provide `cwe_id` for a direct lookup (e.g. CWE-79) or `search` for discovery by name; a request
    naming neither is rejected with `422`.
    Returns the weakness with associated attack patterns and the ATT&CK techniques those patterns map
    to, connecting root cause to adversary behavior. The technique layer is resolved from this
    weakness's
    CAPEC links, so it is only as complete as those links are: a CAPEC carrying no ATT&CK mapping
    contributes none, and mitigation and detection guidance covers the techniques that do resolve —
    there is none when the linked CAPECs carry no mappings.

    **Include options**

    - `details` — CWE object with name, description, and severity
    - `capecs` — attack patterns linked to this weakness class
    - `techniques` — ATT&CK techniques linked to this weakness class
    - `tie` — technique likelihood predictions for resolved techniques
    - `navigator` — ATT&CK Navigator layer JSON for resolved techniques
    - `groups` — threat actor groups using the linked techniques
    - `software` — malware and tools using the linked techniques
    - `campaigns` — threat campaigns using the linked techniques
    - `mitigations` — defensive courses of action per technique
    - `detections` — detection data sources per technique
    - `defend` — D3FEND defensive techniques and countermeasures
    - `cves` — CVEs referencing this weakness (queried by weakness id, independent of the technique
    layer)
    - `knowledgebase` — related intelligence from the knowledge base
    - `summary` — AI-generated summary of the weakness and its attack implications
    - `nist_controls` *(opt-in)* — NIST SP 800-53 rev 5 controls that mitigate the linked techniques,
      based on MITRE Center for Threat-Informed Defense mappings

    The technique-derived layers — `groups`, `software`, `campaigns`, `mitigations`, `detections`,
    `defend` and `nist_controls` — read the resolved technique set, and this endpoint resolves that
    set itself from the weakness' CAPEC links, so each one answers when asked for ALONE and publishes
    only its own section. `techniques[]` is the carrier that stays tied to the CAPEC walk rather than
    to its own token: measured 2026-09-13 on CWE-522, `techniques`=0 with `['details','techniques']`
    against `attack_patterns`=13 / `techniques`=12 with `['details','capecs','techniques']` — while a
    `['nist_controls']`-only request maps that same CAPEC-linked set instead of short-circuiting to
    `[]` (verified live 2026-10-15: CWE-522 alone → 198 controls, identical to the `capecs`-included
    request; CWE-79 resolves no technique at all, so its `nist_controls` is empty in every shape).

    Args:
        body (EnrichCWERequest): Enrich a weakness classification with linked attack patterns and
            their ATT&CK mappings.

            Techniques resolve from this weakness's CAPEC links, so the layer is only as complete as
            those
            links are: a CAPEC carrying no ATT&CK mapping contributes none, and the layers derived
            from
            techniques are empty with it. Some weaknesses carry no CAPECs at all.
            Supply at least one of `cwe_id` or `search`.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichCWEResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
