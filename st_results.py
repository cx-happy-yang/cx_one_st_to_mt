import sqlite3
from typing import List
from CheckmarxPythonSDK.CxOne import (
    get_all_projects,
    get_branches,
    get_a_list_of_scans,
    get_sast_results_by_scan_id,
)

import logging

# create logger
logger = logging.getLogger("main")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
time_stamp_format = "%Y-%m-%dT%H:%M:%S.%fZ"

__all__ = ["logger"]


def get_sast_result(project_name: str, branch: str, scan_id: str) -> List[dict]:
    offset = 0
    limit = 100
    page = 1
    sast_results_collection = get_sast_results_by_scan_id(
        scan_id=scan_id, offset=offset, limit=limit,
        sort=["+status", "+severity", "-queryname"]
    )
    total_count = int(sast_results_collection.get("totalCount"))
    sast_results = sast_results_collection.get("results")
    if total_count > limit:
        while True:
            offset = page * limit
            if offset >= total_count:
                break
            sast_results_collection = get_sast_results_by_scan_id(
                scan_id=scan_id, offset=offset, limit=limit,
                sort=["+status", "+severity", "-queryname"]
            )
            page += 1
            sast_results.extend(sast_results_collection.get("results"))
    report_content = []
    for result in sast_results:
        if result.state == "TO_VERIFY":
            continue
        report_content.append(
            {
                "id": None,
                "project_name": project_name,
                "branch": branch,
                "cwe_id": result.cwe_id,
                "language_name": result.language_name,
                "query_group": result.query_group,
                "query": result.query_name,
                "source_file_name": result.nodes[0].fileName,
                "source_line": result.nodes[0].line,
                "source_column": result.nodes[0].column,
                "source_name": result.nodes[0].fullName,
                "dest_file_name": result.nodes[-1].fileName,
                "dest_line": result.nodes[-1].line,
                "dest_column": result.nodes[-1].column,
                "dest_name": result.nodes[-1].fullName,
                "result_state": result.state,
                "result_severity": result.severity,
                "comment": "",
                "similarity_id": result.similarity_id,
            }
        )
    return report_content


sql_create_table = """
CREATE TABLE IF NOT EXISTS results (
id INTEGER PRIMARY KEY AUTOINCREMENT,
project_name TEXT,
branch TEXT,
cwe_id INTEGER,
language_name TEXT,
query_group TEXT,
query TEXT,
source_file_name TEXT,
source_line INTEGER,
source_column INTEGER,
source_name TEXT,
dest_file_name TEXT,
dest_line INTEGER,
dest_column INTEGER,
dest_name TEXT,
result_state TEXT,
result_severity TEXT,
comment TEXT,
similarity_id INTEGER
);
"""

sql_create_index = "CREATE INDEX IF NOT EXISTS result_index ON results (project_name, branch)"

sql_insert_table = """
INSERT INTO results VALUES (
:id,
:project_name,
:branch,
:cwe_id,
:language_name,
:query_group,
:query,
:source_file_name,
:source_line,
:source_column,
:source_name,
:dest_file_name,
:dest_line,
:dest_column,
:dest_name,
:result_state,
:result_severity,
:comment,
:similarity_id
)
"""


def insert_into_db(result_data: List[dict]):
    logger.info("insert data into database results.db")
    con = sqlite3.connect("results.db")
    logger.info(f"run sql: {sql_create_table}")
    con.execute(sql_create_table)
    logger.info(f"run sql: {sql_create_index}")
    con.execute(sql_create_index)
    try:
        with con:
            con.executemany(sql_insert_table, result_data)
    except sqlite3.IntegrityError:
        print("couldn't add data twice")

    # Connection object used as context manager only commits or rollbacks transactions,
    # so the connection object should be closed manually
    con.close()


def get_project_branch_from_db():
    result = set()
    con = sqlite3.connect("results.db")
    logger.info(f"run sql: {sql_create_table}")
    con.execute(sql_create_table)
    logger.info(f"run sql: {sql_create_index}")
    con.execute(sql_create_index)
    try:
        with con:
            for row in con.execute("SELECT project_name, branch FROM results"):
                result.add((row[0], row[1]))
    except sqlite3.IntegrityError:
        print("couldn't add data twice")
    con.close()
    return list(result)


if __name__ == '__main__':
    projects = get_all_projects()
    projects_branches_in_db = get_project_branch_from_db()
    for project in projects:
        project_id = project.id
        project_name = project.name
        if project_name in ["CxPSEMEA-Query Migration Project"]:
            continue
        branches = get_branches(limit=2048, project_id=project_id)
        if not branches:
            continue
        for branch in branches:
            logger.info(f"project_name: {project_name}, branch: {branch}")
            filtered_pb = list(filter(lambda r: r[0] == project_name and r[1] == branch, projects_branches_in_db))
            if filtered_pb:
                logger.info(f"branch already exist in database! Skip!")
                continue
            logger.info("get last scan")
            scans_collection = get_a_list_of_scans(limit=1, project_id=project_id, branch=branch, sort=["-created_at"])
            if not scans_collection.scans:
                continue
            scan_id = scans_collection.scans[0].id
            logger.info(f"scan id: {scan_id}")
            scan_result = get_sast_result(project_name, branch, scan_id)
            logger.info(f"get last scan result")
            if not scan_result:
                logger.info("No scan result, Skip!")
                continue
            insert_into_db(scan_result)
