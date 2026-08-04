from dataclasses import dataclass

@dataclass(slots=True)
class Dependency:
    name: str
    version: str | None
    ecosystem: str

