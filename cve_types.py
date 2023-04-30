from dataclasses import dataclass
from typing import Callable, List

from data_utils import group_by


@dataclass
class ToolName:
    Clair: str = "clair"
    Grype: str = "grype"
    Snyk: str = "snyk"
    Trivy: str = "trivy"


@dataclass
class CVEState:
    FIXED: str = "fixed"
    UNFIXED: str = "unfixed"
    UNKNOWN: str = "unknown"


@dataclass
class CVEData:
    CVEId: str
    artifacts: str
    version: str | None
    fixed_version: str | None
    state: str
    tool_name: str

    # where the data is load from
    source: str | None = None


class CVEDataCollection:
    def __init__(self, cve_datas: List[CVEData]) -> None:
        self.__cve_datas = cve_datas
        self.__indices = dict()

    def make_index(self, index_name, get_key):
        if index_name in self.__indices:
            return
        self.__indices[index_name] = group_by(self.__cve_datas, get_key)

    def find(self, index_name, key):
        index = self.__indices[index_name]
        return index.get(key)


@dataclass
class Tool:
    name: str
    loader: Callable


