import sys
import pandas as pd
from sqlalchemy import create_engine

sys.path.append('.')

import cve_types
import dataloader
import data_utils

if __name__ == '__main__':
    cve_datas = dataloader.load_all_datas()
    # print("total:", len(cve_datas))

    # db
    engine = create_engine('mysql+pymysql://root:123456@localhost:3306/imagescan')
    # store all cve
    # df = pd.DataFrame(cve_datas)
    # df.to_sql('cve-test',engine)

    # store grouped by tool_name
    # Clair
    # group_by_tool_name = data_utils.group_by(cve_datas, lambda i: i.tool_name)
    # df = pd.DataFrame(group_by_tool_name[cve_types.ToolName.Clair])
    # df.to_sql('cve_test_clair2', engine)
    # Grype
    group_by_tool_name = data_utils.group_by(cve_datas, lambda i: i.tool_name)
    df = pd.DataFrame(group_by_tool_name[cve_types.ToolName.Grype])
    df.to_sql('cve_test_grype8', engine)
    # Snyk
    # group_by_tool_name = data_utils.group_by(cve_datas, lambda i: i.tool_name)
    # df = pd.DataFrame(group_by_tool_name[cve_types.ToolName.Snyk])
    # df.to_sql('cve_test_snyk2', engine)
    # # Trivy
    # group_by_tool_name = data_utils.group_by(cve_datas, lambda i: i.tool_name)
    # df = pd.DataFrame(group_by_tool_name[cve_types.ToolName.Trivy])
    # df.to_sql('cve_test_trivy2', engine)


    # print(df.describe())
    # print(len(group_by_tool_name[cve_types.ToolName.Clair]))

    # BUG
    # print(set([i.version for i in group_by_tool_name[cve_types.ToolName.Trivy]]))

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
