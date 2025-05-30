import pickle
import sqlite3
from typing import List
from CheckmarxPythonSDK.CxOne import (
    get_all_projects,
    get_branches,
    get_a_list_of_scans,
    get_sast_results_by_scan_id,
    predicate_severity_and_state_by_similarity_id_and_project_id,

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


def get_all_sast_result_by_scan_id(scan_id):
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
    return sast_results


def get_predicates_data_from_db(project_name: str, branch: str) -> dict:
    result = {}
    con = sqlite3.connect("results.db")
    logger.info("get data from database")
    try:
        with con:
            for row in con.execute(
                    f"""SELECT project_name, branch, result_state, result_severity, comment, similarity_id FROM results
                where project_name={project_name} and branch={branch}
                """
            ):
                result_state = row[2]
                result_severity = row[3]
                comment = row[4]
                similarity_id = int(row[5])
                result.update({
                    similarity_id: {
                        "result_state": result_state,
                        "result_severity": result_severity,
                        "comment": comment,
                    }
                })
    except sqlite3.IntegrityError:
        print("couldn't read data twice")
    con.close()
    return result


pickle_file_name = "processed_project_branch.pickle"


def read_from_project_branch_pickle_file() -> dict:
    try:
        with open(pickle_file_name, 'rb') as f:
            data = pickle.load(f)
        return data
    except FileExistsError:
        return {}


def write_into_project_branch_pickle_file(project_name, branch):
    data = read_from_project_branch_pickle_file()
    branches = data.get(project_name)
    if not branches:
        data.update({project_name: [branch]})
    else:
        data.update({project_name: branches.append(branch)})
    with open(pickle_file_name, "rwb") as f:
        pickle.dump(data, f, pickle.HIGHEST_PROTOCOL)


def apply_predicates(scan_results, predicates_data: dict, project_id: str, scan_id: str):
    request_body: List[dict] = []
    for scan_result in scan_results:
        similarity_id = scan_result.similarity_id
        if similarity_id not in predicates_data.keys():
            logger.info("similarity_id does not exist in predicates_data keys! skip!")
            continue
        result_severity = predicates_data.get(similarity_id).get("result_severity")
        result_state = predicates_data.get(similarity_id).get("result_state")
        comment = predicates_data.get(similarity_id).get("comment")
        request_body.append(
            {
                "similarityId": similarity_id,
                "projectId": project_id,
                "scanId": scan_id,
                "severity": result_severity,
                "state": result_state,
                "comment": comment
            }
        )
    predicate_severity_and_state_by_similarity_id_and_project_id(request_body=request_body)


if __name__ == '__main__':
    projects = get_all_projects()
    project_branches_from_pickle = read_from_project_branch_pickle_file()
    for project in projects:
        project_id = project.id
        project_name = project.name
        if project_name in ["CxPSEMEA-Query Migration Project"]:
            continue
        branches_already_processed = project_branches_from_pickle.get(project_name) or []
        branches = get_branches(limit=2048, project_id=project_id)
        if not branches:
            logger.info(f"project: {project_name} has no branches")
            continue
        for branch in branches:
            if branch not in ["master", "main", "release", "rc", "develop", "stage"]:
                continue
            logger.info(f"project_name: {project_name}, branch: {branch}")
            if branch in branches_already_processed:
                logger.info(f"branch already processed! Skip!")
                continue
            logger.info("get last scan")
            scans_collection = get_a_list_of_scans(limit=1, project_id=project_id, branch=branch, sort=["-created_at"])
            if not scans_collection.scans:
                logger.info("this project has no scan yet. Skip!")
                continue
            scan_id = scans_collection.scans[0].id
            logger.info(f"scan id: {scan_id}")
            scan_results = get_all_sast_result_by_scan_id(scan_id)
            logger.info(f"get last scan result")
            if not scan_results:
                logger.info("No scan result, Skip!")
                continue
            predicates_data = get_predicates_data_from_db(project_name=project_name, branch=branch)
            apply_predicates(
                scan_results=scan_results, predicates_data=predicates_data, project_id=project_id, scan_id=scan_id
            )
