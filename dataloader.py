import os
import json
from itertools import product
from pathlib import Path
from typing import List, Dict

from data_utils import first_of, resolve_nested_dict, iter_nested_dict
from cve_types import CVEData, CVEState, ToolName, Tool


def walkdir(dir: Path):
    for dirpath, dirnames, filenames in os.walk(dir):
        print(dirpath, dirnames, filenames)


# Return a list containing the names of the files in the directory
def get_image_names(dir: Path):
    return os.listdir(dir)


def load_clair(json_data: Dict) -> List[CVEData]:
    def __fix_version_format(fixed_version: str) -> str:
        if fixed_version == "":
            return ""
        if ':' not in fixed_version:
            fixed_version = '0:' + fixed_version
        return fixed_version

    def __version_format(version: str) -> str:
        if version == "":
            return ""
        if ":" not in version:
            version = '0:' + version
        return version

    def __compare_version(version: str, fixed_version: str) -> CVEState:
        if version == "" | fixed_version == "":
            state = CVEState.UNKNOWN
        if float(version) >= float(fixed_version) | version in fixed_version:
            state = CVEState.FIXED
        if float(version) < float(fixed_version):
            state = CVEState.UNFIXED
        return state

    cve_datas = []
    for feature in iter_nested_dict(json_data, ['vulnerabilities']):
        cve_datas.append(CVEData(
            CVEId=feature['vulnerability'],
            artifacts=feature['featurename'],
            version=__version_format(feature['featureversion']),
            fixed_version=__fix_version_format(feature['fixedby']),
            # state=__compare_version(version=__version_format(feature['featureversion']),
            #                         fixed_version=__fix_version_format(feature['fixedby'])),
            state=CVEState.UNKNOWN,
            tool_name=ToolName.Clair,
        ))
    return cve_datas


def load_grype(json_data: Dict) -> List[CVEData]:
    cve_datas = []
    for match in iter_nested_dict(json_data, ['matches']):
        state = resolve_nested_dict(match, ['vulnerability', 'fix', 'state'])
        if state == 'wont-fix' or state == 'not-fixed':
            state = CVEState.UNFIXED

        feature = list(iter_nested_dict(match, ['matchDetails', 'searchedBy', 'package']))
        if len(feature) == 0:
            artifact = resolve_nested_dict(match, ['artifact', 'name'])
            version = resolve_nested_dict(match, ['artifact', 'version'])
        elif len(feature) == 1:
            artifact = feature[0]['name']
            version = feature[0]['version']
        else:
            raise f'more than 1 feature: {feature}'

        cve_datas.append(CVEData(
            CVEId=resolve_nested_dict(match, ['vulnerability', 'id']),
            artifacts=artifact,
            version=version,
            fixed_version=None,
            state=state,
            tool_name=ToolName.Grype,
        ))
    return cve_datas


def load_snyk(json_data: Dict) -> List[CVEData]:
    def __version_format(version: str) -> str:
        if version == "":
            return ""
        if ":" not in version:
            version = "0:" + version

    def __fixed_version_format(version: str) -> str:
        if version == "":
            return ""
        if ":" not in version:
            version = '0:' + version
        return version

    cve_datas = []
    for feature in iter_nested_dict(json_data, ['vulnerabilities']):
        id_cve = resolve_nested_dict(feature, ['identifiers', 'CVE'])
        id_cwe = resolve_nested_dict(feature, ['identifiers', 'CWE'])
        id_ersa = resolve_nested_dict(feature, ['identifiers', 'ELSA'])
        cve_id = first_of(id_cve, id_cwe, id_ersa)

        cve_datas.append(CVEData(
            CVEId=cve_id,
            artifacts=feature['name'],
            version=__version_format(feature['version']),
            fixed_version=(None if 'nearestFixedInVersion' not in feature
                           else feature['nearestFixedInVersion']),
            state=CVEState.UNKNOWN,
            tool_name=ToolName.Snyk,
        ))
    return cve_datas


def load_trivy(json_data: Dict) -> List[CVEData]:
    cve_datas = []
    for feature in iter_nested_dict(json_data, ['Results', 'Vulnerabilities']):
        cve_datas.append(CVEData(
            CVEId=feature['VulnerabilityID'],
            artifacts=feature['PkgName'],
            version=feature['InstalledVersion'],
            fixed_version=None if 'FixedVersion' not in feature else feature['FixedVersion'],
            state=CVEState.UNKNOWN,
            tool_name=ToolName.Trivy,
        ))
    return cve_datas


def load_file(data_path, image_type, tool):
    image_names = get_image_names(data_path / image_type)
    for image_name in image_names:
        json_path = data_path / Path(image_type) / \
                    image_name / Path(tool.name + ".json")
        if not json_path.exists():
            continue
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        cve_datas = tool.loader(data)
        if not cve_datas:
            # print(json_path)
            continue
        for cve_data in cve_datas:
            cve_data.source = json_path
        yield cve_datas


def load_all_datas():
    data_path = Path('file')
    image_type_official = 'Official'
    image_type_sponsored = 'Sponsored'
    image_type_verified = 'Verified'

    tool_clair = Tool(name="Clair", loader=load_clair)
    tool_grype = Tool(name="Grype", loader=load_grype)
    tool_snyk = Tool(name="Snyk", loader=load_snyk)
    tool_trivy = Tool(name="Trivy", loader=load_trivy)

    # load_all_datas
    cve_datas = []
    for image_type, tool in product([image_type_official, image_type_sponsored, image_type_verified],
                                    [tool_clair, tool_grype, tool_snyk, tool_trivy]):
        for data in load_file(data_path, image_type, tool):
            if not data:
                continue
            cve_datas.extend(data)
    return cve_datas