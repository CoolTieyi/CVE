import logging
import sys
import pandas as pd
from sqlalchemy import create_engine
from scrapy.crawler import CrawlerProcess

sys.path.append('.')

# import dataloader
from data_utils import NvdSpider
# from data_utils import version_format, NvdSpider, group_by, sql_to_CVEData
import cve_types

def sql_to_CVEData(sql_query, engine):
    df_read = pd.read_sql_query(sql_query, engine)
    deduplicated_cve_datas = []
    for i in range(len(df_read)):
        h = cve_types.CVEData(
            df_read.iloc[i]['CVEId'],
            df_read.iloc[i]['artifacts'],
            df_read.iloc[i]['version'],
            df_read.iloc[i]['fixed_version'],
            df_read.iloc[i]['format_version'],
            df_read.iloc[i]['format_fixed_version'],
            df_read.iloc[i]['nvd_version'],
            df_read.iloc[i]['state'],
            df_read.iloc[i]['isVulner'],
            df_read.iloc[i]['tool_name'],
            df_read.iloc[i]['source'],
        )
        deduplicated_cve_datas.append(h)
    return deduplicated_cve_datas


if __name__ == '__main__':

    # 1. 从文件中获取CVE
    # cve_datas = dataloader.load_all_datas()
    # print("total:", len(cve_datas))
    # print(type(cve_datas))
    # print(type(cve_datas[0]))
    #
    # # 2. 统一版本格式
    # # format_version
    # for i in cve_datas:
    #     i.format_version = version_format(i.version)
    #     i.format_fixed_version = version_format(i.fixed_version)

    # 3. 将cve_datas 写入database
    # engine = create_engine('mysql+pymysql://root:123456@localhost:3306/imagescan')
    # # store all cve
    # # df = pd.DataFrame(cve_datas)
    # # df.to_sql('0629-test04',engine,index= True)
    #
    # # GROUP
    # group_by_tool_name = group_by(cve_datas, lambda i: i.tool_name)
    #
    # # store grouped by tool_name
    # df_clair = pd.DataFrame(group_by_tool_name[cve_types.ToolName.Clair])
    # df_clair.to_sql('0702clair', engine)
    #
    # df_grype = pd.DataFrame(group_by_tool_name[cve_types.ToolName.Grype])
    # df_grype.to_sql('0702grype', engine)
    #
    # df_snyk = pd.DataFrame(group_by_tool_name[cve_types.ToolName.Snyk])
    # df_snyk.to_sql('0702snyk', engine)
    #
    # df_tyivy = pd.DataFrame(group_by_tool_name[cve_types.ToolName.Trivy])
    # df_tyivy.to_sql('0702trivy', engine)

    # 4. 去重，区分shadowcve和semicve

    # 5. 重新从数据库中获得筛选后的结果
    engine = create_engine('mysql+pymysql://root:123456@localhost:3306/imagescan')
    # clair_sql_query = 'select * from 0702clair'
    # grype_sql_query = 'select * from 0702grype'
    # snyk_sql_query = 'select * from 0702snyk'
    trivy_sql_query = 'select * from 0702trivy'

    # clair_deduplicated_cve_data = sql_to_CVEData(clair_sql_query, engine)
    # grype_deduplicated_cve_data = sql_to_CVEData(grype_sql_query, engine)
    # snyk_deduplicated_cve_data = sql_to_CVEData(snyk_sql_query, engine)
    trivy_deduplicated_cve_data = sql_to_CVEData(trivy_sql_query, engine)


    # 6. 对筛查后的unicve和semicve 通过API访问nvd数据库，得到修复的版本
    process = CrawlerProcess(settings={
        'LOG_ENABLED': False
    })
    # process.crawl(NvdSpider, clair_deduplicated_cve_data)
    # process.crawl(NvdSpider, grype_deduplicated_cve_data)
    # process.crawl(NvdSpider, snyk_deduplicated_cve_data)
    process.crawl(NvdSpider, trivy_deduplicated_cve_data)
    process.start()


    # 7. 将查完的api重新写进数据库
    # df = pd.DataFrame(cve_datas)
    # df.to_sql('0629-test04',engine,index= True)

    # store grouped by tool_name
    # df_clair = pd.DataFrame(clair_deduplicated_cve_data)
    # df_clair.to_sql('0707clair', engine)

    # df_grype = pd.DataFrame(grype_deduplicated_cve_data)
    # df_grype.to_sql('0707grype', engine)
    #
    # df_snyk = pd.DataFrame(snyk_deduplicated_cve_data)
    # df_snyk.to_sql('0706snyk', engine)
    #
    df_tyivy = pd.DataFrame(trivy_deduplicated_cve_data)
    df_tyivy.to_sql('0707trivy', engine)

# print(df.describe())
# print(len(group_by_tool_name[cve_types.ToolName.Clair]))

# BUG
# print(set([i.version for i in group_by_tool_name[cve_types.ToolName.Trivy]]))

# print(set([i.version for i in group_by_tool_name[cve_types.ToolName.Clair]]))
# print(set([i.fixed_version for i in group_by_tool_name[cve_types.ToolName.Clair]]))
# print(set([i.fixed_version for i in group_by_tool_name[cve_types.ToolName.Grype]]))

# MAKE SEARCHING INDEX
# cve_collection = cve_types.CVEDataCollection(cve_datas)
# cve_collection.make_index("cve_id", lambda data: data.CVEId)
# print(cve_collection.find("cve_id", 'CVE-2022-23648'))

# cve_collection.make_index("tool_name", lambda data: data.tool_name)
# print(cve_collection.find("tool_name", cve_types.ToolName.Clair))

# group_by_tool_name = data_utils.group_by(cve_datas, lambda i: i.state)
# print(group_by_tool_name.keys())
# cve_ids = [i.CVEId for i in group_by_tool_name['unknown']]
# print(len(set(cve_ids)))
