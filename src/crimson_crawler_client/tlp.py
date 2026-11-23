"""TLP 2.0 marking values for the export surfaces (#374).

One module-level value set shared by the Artifact Manager / Report Generator surfaces and the
``/v1/artifact-enrich`` engine. Case-sensitive: the five CISA TLP 2.0 markings. Every storage
artifact now carries its own ``tlp`` (contract #374), so ``None`` (the default on every method here)
omits the parameter: list methods return all markings, new artifacts default to ``AMBER``, and
stored-artifact exports use the artifact's own TLP. Nothing defaults to ``CLEAR``, because no
deterministic signal proves an input is public reference data.
"""

from __future__ import annotations

from typing import Literal, get_args

Tlp = Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]

TLP_VALUES: tuple[Tlp, ...] = get_args(Tlp)

TLP_INVALID_MESSAGE = f"tlp must be one of {', '.join(TLP_VALUES)}"


def validate_tlp(value: str | None) -> Tlp | None:
    """Validate a wire ``tlp`` argument, or ``None`` to omit it (server default: AMBER, or the
    artifact's own stored TLP on a stored-artifact export).

    Raises :class:`ValueError` — the SDK's argument-validation error — BEFORE any request is made.
    """
    if value is None:
        return None
    if value in TLP_VALUES:
        return value
    raise ValueError(TLP_INVALID_MESSAGE)


__all__ = ["TLP_INVALID_MESSAGE", "TLP_VALUES", "Tlp", "validate_tlp"]
