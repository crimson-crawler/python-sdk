from enum import StrEnum


class SearchKnowledgebaseRequestCollectionsItem(StrEnum):
    LARGE = "large"
    MAIN = "main"
    RED_TEAM = "red_team"
    USER = "user"

    def __str__(self) -> str:
        return str(self.value)
