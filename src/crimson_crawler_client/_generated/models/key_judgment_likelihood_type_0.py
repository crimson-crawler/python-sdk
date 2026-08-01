from enum import Enum


class KeyJudgmentLikelihoodType0(str, Enum):
    ALMOST_CERTAIN = "almost_certain"
    ALMOST_NO_CHANCE = "almost_no_chance"
    LIKELY = "likely"
    ROUGHLY_EVEN_CHANCE = "roughly_even_chance"
    UNLIKELY = "unlikely"
    VERY_LIKELY = "very_likely"
    VERY_UNLIKELY = "very_unlikely"

    def __str__(self) -> str:
        return str(self.value)
