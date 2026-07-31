from enum import Enum


class AdmiraltyGradeReliability(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"

    def __str__(self) -> str:
        return str(self.value)
