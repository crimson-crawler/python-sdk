from enum import Enum


class SearchKnowledgebaseRequestCollectionsItem(str, Enum):
    LARGE = "large"
    MAIN = "main"
    RED_TEAM = "red_team"
    USER = "user"

    def __str__(self) -> str:
        return str(self.value)
