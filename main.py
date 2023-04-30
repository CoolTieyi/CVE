import sys

sys.path.append('.')

import cve_types
import dataloader
import data_utils

# import requests
#
#
# def filter_clair(cve_datas):
#     for cve_data in cve_datas:
#         pass
#

if __name__ == '__main__':
    cve_datas = dataloader.load_all_datas()
    print("total:", len(cve_datas))

    group_by_tool_name = data_utils.group_by(cve_datas, lambda i: i.tool_name)

    # BUG
    # Grype version == None???
    print(([i.version for i in group_by_tool_name[cve_types.ToolName.Grype]]))

    # print(set([i.version for i in group_by_tool_name[cve_types.ToolName.Clair]]))
    # print(set([i.fixed_version for i in group_by_tool_name[cve_types.ToolName.Clair]]))
    # print(set([i.fixed_version for i in group_by_tool_name[cve_types.ToolName.Grype]]))

    # make searching index
    # cve_collection = cve_types.CVEDataCollection(cve_datas)
    # cve_collection.make_index("cve_id", lambda data: data.CVEId)
    # print(cve_collection.find("cve_id", 'CVE-2022-23648'))

    # cve_collection.make_index("tool_name", lambda data: data.tool_name)
    # print(cve_collection.find("tool_name", cve_types.ToolName.Clair))

    # group_by_tool_name = data_utils.group_by(cve_datas, lambda i: i.state)
    # print(group_by_tool_name.keys())
    # cve_ids = [i.CVEId for i in group_by_tool_name['unknown']]
    # print(len(set(cve_ids)))
