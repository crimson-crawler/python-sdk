from enum import StrEnum


class SearchCTIRequestTypesType0Item(StrEnum):
    ATTACK_PATTERN = "attack-pattern"
    CAMPAIGN = "campaign"
    COURSE_OF_ACTION = "course-of-action"
    INTRUSION_SET = "intrusion-set"
    MALWARE = "malware"
    TOOL = "tool"
    WEAKNESS = "weakness"

    def __str__(self) -> str:
        return str(self.value)
