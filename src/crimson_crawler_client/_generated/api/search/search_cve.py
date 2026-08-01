from http import HTTPStatus
from typing import Any, cast
from urllib.parse import quote

import httpx

from ... import errors
from ...client import AuthenticatedClient, Client
from ...models.search_cve_request import SearchCVERequest
from ...models.search_cve_response import SearchCVEResponse
from ...types import UNSET, Response


def _get_kwargs(
    *,
    body: SearchCVERequest,
) -> dict[str, Any]:
    headers: dict[str, Any] = {}

    _kwargs: dict[str, Any] = {
        "method": "post",
        "url": "/v1/search/cve",
    }

    _kwargs["json"] = body.to_dict()

    headers["Content-Type"] = "application/json"

    _kwargs["headers"] = headers
    return _kwargs


def _parse_response(
    *, client: AuthenticatedClient | Client, response: httpx.Response
) -> Any | SearchCVEResponse | None:
    if response.status_code == 200:
        response_200 = SearchCVEResponse.from_dict(response.json())

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
) -> Response[Any | SearchCVEResponse]:
    return Response(
        status_code=HTTPStatus(response.status_code),
        content=response.content,
        headers=response.headers,
        parsed=_parse_response(client=client, response=response),
    )


def sync_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchCVERequest,
) -> Response[Any | SearchCVEResponse]:
    """Search CVEs

     Search vulnerabilities by ID, weakness, product, severity, exploit status, technique, and date
    range.

    Combine any of the filters below to scope the result set. Each result carries severity, a public-
    exploit
    count, and a weaponization score. Provide at least one search parameter.

    **Filters**

    - `cve_id` — direct CVE lookup (e.g. `CVE-2026-26929`)
    - `query` — compatibility field; free-text matching is not currently supported and this value
      does not filter results
    - `cwe_id` — filter by weakness type (e.g. `CWE-79`)
    - `cpe` — filter by affected product (CPE string)
    - `attack_id` — filter CVEs linked to an ATT&CK technique (e.g. `T1190`)
    - `capec_id` — filter CVEs linked to a CAPEC attack pattern (e.g. `CAPEC-665`)
    - `cvss_min` — minimum CVSS v3.1 base score (`0.0`-`10.0`)
    - `cvss_v2_min` — minimum CVSS v2 base score (`0.0`-`10.0`)
    - `cvss_v4_min` — minimum CVSS v4 base score (`0.0`-`10.0`)
    - `epss_min` — minimum EPSS score (`0.0`-`1.0`)
    - `epss_percentile_min` — minimum EPSS percentile (`0.0`-`1.0`), rank against all CVEs rather than
    the raw score
    - `kev_only` — only return CVEs in the Known Exploited Vulnerabilities catalog
    - `cpes_not_vulnerable` — exclude CVEs requiring (but not vulnerable in) this CPE 2.3 string
    - `created_by_ref` — filter by CNA or numbering-authority identity STIX ID
    - `stix_id` — filter by exact vulnerability STIX ID
    - `modified_min` / `modified_max` — restrict to a modification-date range
    - `created_min` / `created_max` — restrict to a creation-date range
    - `vuln_status` — vulnerability status: `Analyzed`, `Awaiting Analysis`, `Modified`, `Received`,
    `Rejected`

    **Sort options**

    - `created_ascending` — oldest creation date first
    - `created_descending` — newest creation date first
    - `modified_ascending` — oldest modification date first
    - `modified_descending` — newest modification date first
    - `epss_score_descending` — highest EPSS score first
    - `x_opencti_cvss_base_score_descending` — highest CVSS base score first

    **Include options**

    - `details` — full vulnerability detail per result

    Omitted include values return as empty arrays. The `errors` array reports any partial failures.

    Args:
        body (SearchCVERequest): Search vulnerabilities by severity, exploit status, technique,
            weakness, date range, and more.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchCVEResponse]
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
    body: SearchCVERequest,
) -> Any | SearchCVEResponse | None:
    """Search CVEs

     Search vulnerabilities by ID, weakness, product, severity, exploit status, technique, and date
    range.

    Combine any of the filters below to scope the result set. Each result carries severity, a public-
    exploit
    count, and a weaponization score. Provide at least one search parameter.

    **Filters**

    - `cve_id` — direct CVE lookup (e.g. `CVE-2026-26929`)
    - `query` — compatibility field; free-text matching is not currently supported and this value
      does not filter results
    - `cwe_id` — filter by weakness type (e.g. `CWE-79`)
    - `cpe` — filter by affected product (CPE string)
    - `attack_id` — filter CVEs linked to an ATT&CK technique (e.g. `T1190`)
    - `capec_id` — filter CVEs linked to a CAPEC attack pattern (e.g. `CAPEC-665`)
    - `cvss_min` — minimum CVSS v3.1 base score (`0.0`-`10.0`)
    - `cvss_v2_min` — minimum CVSS v2 base score (`0.0`-`10.0`)
    - `cvss_v4_min` — minimum CVSS v4 base score (`0.0`-`10.0`)
    - `epss_min` — minimum EPSS score (`0.0`-`1.0`)
    - `epss_percentile_min` — minimum EPSS percentile (`0.0`-`1.0`), rank against all CVEs rather than
    the raw score
    - `kev_only` — only return CVEs in the Known Exploited Vulnerabilities catalog
    - `cpes_not_vulnerable` — exclude CVEs requiring (but not vulnerable in) this CPE 2.3 string
    - `created_by_ref` — filter by CNA or numbering-authority identity STIX ID
    - `stix_id` — filter by exact vulnerability STIX ID
    - `modified_min` / `modified_max` — restrict to a modification-date range
    - `created_min` / `created_max` — restrict to a creation-date range
    - `vuln_status` — vulnerability status: `Analyzed`, `Awaiting Analysis`, `Modified`, `Received`,
    `Rejected`

    **Sort options**

    - `created_ascending` — oldest creation date first
    - `created_descending` — newest creation date first
    - `modified_ascending` — oldest modification date first
    - `modified_descending` — newest modification date first
    - `epss_score_descending` — highest EPSS score first
    - `x_opencti_cvss_base_score_descending` — highest CVSS base score first

    **Include options**

    - `details` — full vulnerability detail per result

    Omitted include values return as empty arrays. The `errors` array reports any partial failures.

    Args:
        body (SearchCVERequest): Search vulnerabilities by severity, exploit status, technique,
            weakness, date range, and more.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchCVEResponse
    """

    return sync_detailed(
        client=client,
        body=body,
    ).parsed


async def asyncio_detailed(
    *,
    client: AuthenticatedClient,
    body: SearchCVERequest,
) -> Response[Any | SearchCVEResponse]:
    """Search CVEs

     Search vulnerabilities by ID, weakness, product, severity, exploit status, technique, and date
    range.

    Combine any of the filters below to scope the result set. Each result carries severity, a public-
    exploit
    count, and a weaponization score. Provide at least one search parameter.

    **Filters**

    - `cve_id` — direct CVE lookup (e.g. `CVE-2026-26929`)
    - `query` — compatibility field; free-text matching is not currently supported and this value
      does not filter results
    - `cwe_id` — filter by weakness type (e.g. `CWE-79`)
    - `cpe` — filter by affected product (CPE string)
    - `attack_id` — filter CVEs linked to an ATT&CK technique (e.g. `T1190`)
    - `capec_id` — filter CVEs linked to a CAPEC attack pattern (e.g. `CAPEC-665`)
    - `cvss_min` — minimum CVSS v3.1 base score (`0.0`-`10.0`)
    - `cvss_v2_min` — minimum CVSS v2 base score (`0.0`-`10.0`)
    - `cvss_v4_min` — minimum CVSS v4 base score (`0.0`-`10.0`)
    - `epss_min` — minimum EPSS score (`0.0`-`1.0`)
    - `epss_percentile_min` — minimum EPSS percentile (`0.0`-`1.0`), rank against all CVEs rather than
    the raw score
    - `kev_only` — only return CVEs in the Known Exploited Vulnerabilities catalog
    - `cpes_not_vulnerable` — exclude CVEs requiring (but not vulnerable in) this CPE 2.3 string
    - `created_by_ref` — filter by CNA or numbering-authority identity STIX ID
    - `stix_id` — filter by exact vulnerability STIX ID
    - `modified_min` / `modified_max` — restrict to a modification-date range
    - `created_min` / `created_max` — restrict to a creation-date range
    - `vuln_status` — vulnerability status: `Analyzed`, `Awaiting Analysis`, `Modified`, `Received`,
    `Rejected`

    **Sort options**

    - `created_ascending` — oldest creation date first
    - `created_descending` — newest creation date first
    - `modified_ascending` — oldest modification date first
    - `modified_descending` — newest modification date first
    - `epss_score_descending` — highest EPSS score first
    - `x_opencti_cvss_base_score_descending` — highest CVSS base score first

    **Include options**

    - `details` — full vulnerability detail per result

    Omitted include values return as empty arrays. The `errors` array reports any partial failures.

    Args:
        body (SearchCVERequest): Search vulnerabilities by severity, exploit status, technique,
            weakness, date range, and more.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Response[Any | SearchCVEResponse]
    """

    kwargs = _get_kwargs(
        body=body,
    )

    response = await client.get_async_httpx_client().request(**kwargs)

    return _build_response(client=client, response=response)


async def asyncio(
    *,
    client: AuthenticatedClient,
    body: SearchCVERequest,
) -> Any | SearchCVEResponse | None:
    """Search CVEs

     Search vulnerabilities by ID, weakness, product, severity, exploit status, technique, and date
    range.

    Combine any of the filters below to scope the result set. Each result carries severity, a public-
    exploit
    count, and a weaponization score. Provide at least one search parameter.

    **Filters**

    - `cve_id` — direct CVE lookup (e.g. `CVE-2026-26929`)
    - `query` — compatibility field; free-text matching is not currently supported and this value
      does not filter results
    - `cwe_id` — filter by weakness type (e.g. `CWE-79`)
    - `cpe` — filter by affected product (CPE string)
    - `attack_id` — filter CVEs linked to an ATT&CK technique (e.g. `T1190`)
    - `capec_id` — filter CVEs linked to a CAPEC attack pattern (e.g. `CAPEC-665`)
    - `cvss_min` — minimum CVSS v3.1 base score (`0.0`-`10.0`)
    - `cvss_v2_min` — minimum CVSS v2 base score (`0.0`-`10.0`)
    - `cvss_v4_min` — minimum CVSS v4 base score (`0.0`-`10.0`)
    - `epss_min` — minimum EPSS score (`0.0`-`1.0`)
    - `epss_percentile_min` — minimum EPSS percentile (`0.0`-`1.0`), rank against all CVEs rather than
    the raw score
    - `kev_only` — only return CVEs in the Known Exploited Vulnerabilities catalog
    - `cpes_not_vulnerable` — exclude CVEs requiring (but not vulnerable in) this CPE 2.3 string
    - `created_by_ref` — filter by CNA or numbering-authority identity STIX ID
    - `stix_id` — filter by exact vulnerability STIX ID
    - `modified_min` / `modified_max` — restrict to a modification-date range
    - `created_min` / `created_max` — restrict to a creation-date range
    - `vuln_status` — vulnerability status: `Analyzed`, `Awaiting Analysis`, `Modified`, `Received`,
    `Rejected`

    **Sort options**

    - `created_ascending` — oldest creation date first
    - `created_descending` — newest creation date first
    - `modified_ascending` — oldest modification date first
    - `modified_descending` — newest modification date first
    - `epss_score_descending` — highest EPSS score first
    - `x_opencti_cvss_base_score_descending` — highest CVSS base score first

    **Include options**

    - `details` — full vulnerability detail per result

    Omitted include values return as empty arrays. The `errors` array reports any partial failures.

    Args:
        body (SearchCVERequest): Search vulnerabilities by severity, exploit status, technique,
            weakness, date range, and more.

    Raises:
        errors.UnexpectedStatus: If the server returns an undocumented status code and Client.raise_on_unexpected_status is True.
        httpx.TimeoutException: If the request takes longer than Client.timeout.

    Returns:
        Any | SearchCVEResponse
    """

    return (
        await asyncio_detailed(
            client=client,
            body=body,
        )
    ).parsed
