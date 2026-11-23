from enum import StrEnum


class HashlookupRecordHashType(StrEnum):
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"

    def __str__(self) -> str:
        return str(self.value)
