from enum import StrEnum


class InventoryAssetAssetClassType0(StrEnum):
    ENGINEERING_WORKSTATION = "engineering_workstation"
    GATEWAY = "gateway"
    HISTORIAN = "historian"
    HMI = "hmi"
    IED = "ied"
    OTHER = "other"
    PLC = "plc"
    RTU = "rtu"
    SENSOR = "sensor"
    SIS = "sis"

    def __str__(self) -> str:
        return str(self.value)
