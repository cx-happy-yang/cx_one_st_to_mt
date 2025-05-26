from CheckmarxPythonSDK.CxOne.KeycloakAPI import (
    get_group_hierarchy,
)
from CheckmarxPythonSDK.CxOne.AccessControlAPI import (
    get_groups,
)
from typing import List
from CheckmarxPythonSDK.CxOne import (
    get_all_projects,
    get_a_list_of_applications,
    get_sast_results_by_scan_id,
)

import logging
import pickle
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


if __name__ == '__main__':
    cxone_tenant_name = "coupangst"
    logger.info("get all groups")
    groups = get_groups(realm=cxone_tenant_name)
    logger.info("get all projects")
    projects = get_all_projects()
    for project in projects:
        project_name = project.name
        project_assigned_group_ids = project.groups
        group_names = []
        for group_id in project_assigned_group_ids:
            logger.info(f"project_name: {project_name}, group_id: {group_id}")
            filtered_groups = list(filter(lambda r: r.id == group_id, groups))
            if filtered_groups:
                group_name = filtered_groups[0].name
                group_names.append(group_name)
        project.groups = group_names
    logger.info("get all applications")
    applications = get_a_list_of_applications(limit=100).applications

    data = {
        "groups": [{"name": group.name} for group in groups],
        "projects": [{
            "criticality": project.criticality,
            "groups": project.groups,
            "mainBranch": project.mainBranch,
            "name": project.name,
            "origin": project.origin,
            "repoUrl": project.repoUrl,
            "tags": project.tags,
        } for project in projects],
        "applications": [{
            "criticality": application.criticality,
            "description": application.description,
            "name": application.name,
            "rules": [{"type": rule.type, "value": rule.value} for rule in application.rules],
            "tags": application.tags,
        } for application in applications],
    }

    with open('data.pkl', 'wb') as file:
        pickle.dump(data, file)
