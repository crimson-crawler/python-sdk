from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, BinaryIO, Generator, TextIO, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.galaxy_parent_kill_chain_order import GalaxyParentKillChainOrder


T = TypeVar("T", bound="GalaxyParent")


@_attrs_define
class GalaxyParent:
    """The Galaxy a cluster belongs to — its name, namespace and kill-chain ordering.

    Attributes:
        description (str | Unset): Galaxy description Default: ''.
        id (str | Unset): Parent galaxy numeric id Default: ''.
        kill_chain_order (GalaxyParentKillChainOrder | Unset): Kill-chain ordering the galaxy defines
        name (str | Unset): Human-readable galaxy name (e.g. 'Attack Pattern') Default: ''.
        namespace (str | Unset): Galaxy namespace (e.g. 'mitre-attack') Default: ''.
        type_ (str | Unset): Galaxy type slug (e.g. 'mitre-attack-pattern') Default: ''.
        version (str | Unset): Galaxy version Default: ''.
    """

    description: str | Unset = ""
    id: str | Unset = ""
    kill_chain_order: GalaxyParentKillChainOrder | Unset = UNSET
    name: str | Unset = ""
    namespace: str | Unset = ""
    type_: str | Unset = ""
    version: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.galaxy_parent_kill_chain_order import GalaxyParentKillChainOrder  # noqa: PLC0415

        description = self.description

        id = self.id

        kill_chain_order: dict[str, Any] | Unset = UNSET
        if not isinstance(self.kill_chain_order, Unset):
            kill_chain_order = self.kill_chain_order.to_dict()

        name = self.name

        namespace = self.namespace

        type_ = self.type_

        version = self.version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if description is not UNSET:
            field_dict["description"] = description
        if id is not UNSET:
            field_dict["id"] = id
        if kill_chain_order is not UNSET:
            field_dict["kill_chain_order"] = kill_chain_order
        if name is not UNSET:
            field_dict["name"] = name
        if namespace is not UNSET:
            field_dict["namespace"] = namespace
        if type_ is not UNSET:
            field_dict["type"] = type_
        if version is not UNSET:
            field_dict["version"] = version

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.galaxy_parent_kill_chain_order import GalaxyParentKillChainOrder  # noqa: PLC0415

        d = dict(src_dict)
        description = d.pop("description", UNSET)

        id = d.pop("id", UNSET)

        _kill_chain_order = d.pop("kill_chain_order", UNSET)
        kill_chain_order: GalaxyParentKillChainOrder | Unset
        if isinstance(_kill_chain_order, Unset):
            kill_chain_order = UNSET
        else:
            kill_chain_order = GalaxyParentKillChainOrder.from_dict(_kill_chain_order)

        name = d.pop("name", UNSET)

        namespace = d.pop("namespace", UNSET)

        type_ = d.pop("type", UNSET)

        version = d.pop("version", UNSET)

        galaxy_parent = cls(
            description=description,
            id=id,
            kill_chain_order=kill_chain_order,
            name=name,
            namespace=namespace,
            type_=type_,
            version=version,
        )

        galaxy_parent.additional_properties = d
        return galaxy_parent

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
