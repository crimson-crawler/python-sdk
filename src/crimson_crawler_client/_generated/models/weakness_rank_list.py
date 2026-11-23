from enum import StrEnum


class WeaknessRankList(StrEnum):
    CWE_TOP25 = "cwe_top25"
    OWASP_API_TOP10 = "owasp_api_top10"
    OWASP_LLM_TOP10 = "owasp_llm_top10"
    OWASP_TOP10 = "owasp_top10"

    def __str__(self) -> str:
        return str(self.value)
