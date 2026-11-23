from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.enrichment_submit_response import EnrichmentSubmitResponse
from ...models.inventory_enrichment_request import InventoryEnrichmentRequest
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: InventoryEnrichmentRequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/inventory-enrich",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | EnrichmentSubmitResponse | None:
    if response.status_code == 202:
        response_202 = EnrichmentSubmitResponse.from_dict(response.json())

        return response_202

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

    if response.status_code == 503:
        response_503 = cast(Any, None)
        return response_503

    if client.raise_on_unexpected_status:
        raise errors.UnexpectedStatus(response.status_code, response.content)
    else:
        return None


def _build_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Response[Any | EnrichmentSubmitResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: InventoryEnrichmentRequest,
) -> Response[Any | EnrichmentSubmitResponse]:
    """Submit Inventory Enrichment

     Submit an asset inventory for asynchronous Inventory Enrichment.

    Returns an `enrichment_id` with HTTP 202. Poll
    `/v1/inventory-enrich/{enrichment_id}` for stage progress and the finished findings.

    Submit 1-1000 assets (at most 200 product assets). Product assets use product, vendor, and up to
    five versions for CPE-based vulnerability matching. Package assets add `ecosystem` and use
    package-advisory matching.
    Asset category, criticality, deployment context, owner, tags, and group metadata are preserved
    in the result. Optional `attachments_text` and `attachments_files` run Artifact Enrichment over
    reports, IOC lists, scans, email, and other evidence attached to the inventory.

    `include` selects the per-CVE evidence retained for each asset and replaces the default list.
    `summary` and `navigator` are accepted for product-schema compatibility
    but intentionally omitted from this deterministic background workflow.

    An ACCEPTED submission (202) consumes one request unit; a refused one (429/503) and every poll
    consume
    none. Each API key can run 3 Artifact, Inventory, or Event Enrichments at once and can hold 20
    running
    or queued jobs across all three enrichment engines (the caps are shared, so the limit binds them
    jointly). Jobs
    beyond the running limit remain `queued`; a full queue returns 429, and that cap is enforced
    atomically, so simultaneous submits cannot push an owner past it. If queue state cannot be
    verified, the request returns 503 and no job is created.

    Args:
        body (InventoryEnrichmentRequest): Submit product and package assets for asynchronous CVE
            findings and a portfolio rollup.

            Product assets use CPE matching. Assets with `ecosystem` set use package-advisory
            matching.
            Each asset can carry deployment and ownership context, which is preserved in the result.
            An optional `vex_overlay` carries VEX statements (OpenVEX 0.2.0 / CSAF 2.0) that mark
            matching
            `not_affected` / `fixed` findings `suppressed_by_vex` — retained with their justification,
            excluded
            from the actionable counts — instead of re-reporting them.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichmentSubmitResponse]
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
    body: InventoryEnrichmentRequest,
) -> Any | EnrichmentSubmitResponse | None:
    """Submit Inventory Enrichment

     Submit an asset inventory for asynchronous Inventory Enrichment.

    Returns an `enrichment_id` with HTTP 202. Poll
    `/v1/inventory-enrich/{enrichment_id}` for stage progress and the finished findings.

    Submit 1-1000 assets (at most 200 product assets). Product assets use product, vendor, and up to
    five versions for CPE-based vulnerability matching. Package assets add `ecosystem` and use
    package-advisory matching.
    Asset category, criticality, deployment context, owner, tags, and group metadata are preserved
    in the result. Optional `attachments_text` and `attachments_files` run Artifact Enrichment over
    reports, IOC lists, scans, email, and other evidence attached to the inventory.

    `include` selects the per-CVE evidence retained for each asset and replaces the default list.
    `summary` and `navigator` are accepted for product-schema compatibility
    but intentionally omitted from this deterministic background workflow.

    An ACCEPTED submission (202) consumes one request unit; a refused one (429/503) and every poll
    consume
    none. Each API key can run 3 Artifact, Inventory, or Event Enrichments at once and can hold 20
    running
    or queued jobs across all three enrichment engines (the caps are shared, so the limit binds them
    jointly). Jobs
    beyond the running limit remain `queued`; a full queue returns 429, and that cap is enforced
    atomically, so simultaneous submits cannot push an owner past it. If queue state cannot be
    verified, the request returns 503 and no job is created.

    Args:
        body (InventoryEnrichmentRequest): Submit product and package assets for asynchronous CVE
            findings and a portfolio rollup.

            Product assets use CPE matching. Assets with `ecosystem` set use package-advisory
            matching.
            Each asset can carry deployment and ownership context, which is preserved in the result.
            An optional `vex_overlay` carries VEX statements (OpenVEX 0.2.0 / CSAF 2.0) that mark
            matching
            `not_affected` / `fixed` findings `suppressed_by_vex` — retained with their justification,
            excluded
            from the actionable counts — instead of re-reporting them.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichmentSubmitResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: InventoryEnrichmentRequest,
) -> Response[Any | EnrichmentSubmitResponse]:
    """Submit Inventory Enrichment

     Submit an asset inventory for asynchronous Inventory Enrichment.

    Returns an `enrichment_id` with HTTP 202. Poll
    `/v1/inventory-enrich/{enrichment_id}` for stage progress and the finished findings.

    Submit 1-1000 assets (at most 200 product assets). Product assets use product, vendor, and up to
    five versions for CPE-based vulnerability matching. Package assets add `ecosystem` and use
    package-advisory matching.
    Asset category, criticality, deployment context, owner, tags, and group metadata are preserved
    in the result. Optional `attachments_text` and `attachments_files` run Artifact Enrichment over
    reports, IOC lists, scans, email, and other evidence attached to the inventory.

    `include` selects the per-CVE evidence retained for each asset and replaces the default list.
    `summary` and `navigator` are accepted for product-schema compatibility
    but intentionally omitted from this deterministic background workflow.

    An ACCEPTED submission (202) consumes one request unit; a refused one (429/503) and every poll
    consume
    none. Each API key can run 3 Artifact, Inventory, or Event Enrichments at once and can hold 20
    running
    or queued jobs across all three enrichment engines (the caps are shared, so the limit binds them
    jointly). Jobs
    beyond the running limit remain `queued`; a full queue returns 429, and that cap is enforced
    atomically, so simultaneous submits cannot push an owner past it. If queue state cannot be
    verified, the request returns 503 and no job is created.

    Args:
        body (InventoryEnrichmentRequest): Submit product and package assets for asynchronous CVE
            findings and a portfolio rollup.

            Product assets use CPE matching. Assets with `ecosystem` set use package-advisory
            matching.
            Each asset can carry deployment and ownership context, which is preserved in the result.
            An optional `vex_overlay` carries VEX statements (OpenVEX 0.2.0 / CSAF 2.0) that mark
            matching
            `not_affected` / `fixed` findings `suppressed_by_vex` — retained with their justification,
            excluded
            from the actionable counts — instead of re-reporting them.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | EnrichmentSubmitResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: InventoryEnrichmentRequest,
) -> Any | EnrichmentSubmitResponse | None:
    """Submit Inventory Enrichment

     Submit an asset inventory for asynchronous Inventory Enrichment.

    Returns an `enrichment_id` with HTTP 202. Poll
    `/v1/inventory-enrich/{enrichment_id}` for stage progress and the finished findings.

    Submit 1-1000 assets (at most 200 product assets). Product assets use product, vendor, and up to
    five versions for CPE-based vulnerability matching. Package assets add `ecosystem` and use
    package-advisory matching.
    Asset category, criticality, deployment context, owner, tags, and group metadata are preserved
    in the result. Optional `attachments_text` and `attachments_files` run Artifact Enrichment over
    reports, IOC lists, scans, email, and other evidence attached to the inventory.

    `include` selects the per-CVE evidence retained for each asset and replaces the default list.
    `summary` and `navigator` are accepted for product-schema compatibility
    but intentionally omitted from this deterministic background workflow.

    An ACCEPTED submission (202) consumes one request unit; a refused one (429/503) and every poll
    consume
    none. Each API key can run 3 Artifact, Inventory, or Event Enrichments at once and can hold 20
    running
    or queued jobs across all three enrichment engines (the caps are shared, so the limit binds them
    jointly). Jobs
    beyond the running limit remain `queued`; a full queue returns 429, and that cap is enforced
    atomically, so simultaneous submits cannot push an owner past it. If queue state cannot be
    verified, the request returns 503 and no job is created.

    Args:
        body (InventoryEnrichmentRequest): Submit product and package assets for asynchronous CVE
            findings and a portfolio rollup.

            Product assets use CPE matching. Assets with `ecosystem` set use package-advisory
            matching.
            Each asset can carry deployment and ownership context, which is preserved in the result.
            An optional `vex_overlay` carries VEX statements (OpenVEX 0.2.0 / CSAF 2.0) that mark
            matching
            `not_affected` / `fixed` findings `suppressed_by_vex` — retained with their justification,
            excluded
            from the actionable counts — instead of re-reporting them.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | EnrichmentSubmitResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
