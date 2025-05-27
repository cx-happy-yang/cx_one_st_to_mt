import pickle
from CheckmarxPythonSDK.CxOne.AccessControlAPI import (
    get_groups,
    get_group_by_name
)
from CheckmarxPythonSDK.CxOne.KeycloakAPI import (
    create_group,
    create_subgroup,
)
from typing import List
from CheckmarxPythonSDK.CxOne import (
    get_a_list_of_applications,
    create_an_application,
    get_a_list_of_projects,
    create_a_project,
    define_parameters_in_the_input_list_for_a_specific_project,
)
from CheckmarxPythonSDK.CxOne.dto import (
    ProjectInput,
    ScanParameter,
    ApplicationInput,
    RuleInput,

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


def get_or_create_groups(
        group_full_name: str,
        cxone_tenant_name: str
) -> str:
    group = get_group_by_name(realm=cxone_tenant_name, group_name=group_full_name)
    if group:
        group_id = group.id
        logger.info(f"group {group_full_name} found. Its id is: {group_id}")
        return group_id
    logger.info(f"group {group_full_name} not found. It contains sub groups.")
    group_id = create_all_groups(cxone_tenant_name=cxone_tenant_name, group_full_name=group_full_name)
    logger.info(f"group {group_full_name} created, id: {group_id}")
    return group_id


def create_all_groups(cxone_tenant_name, group_full_name) -> str:
    group_names = group_full_name.split("/")
    root_group_name = group_names[0]
    root_group_id = create_root_group_if_not_exist(cxone_tenant_name, root_group_name)
    if len(group_names) == 1:
        return root_group_id
    group_id = create_sub_groups(
        cxone_tenant_name=cxone_tenant_name,
        group_names=group_names,
        root_group_id=root_group_id
    )
    return group_id


def create_sub_groups(cxone_tenant_name, group_names, root_group_id) -> str:
    parent_group_id = root_group_id
    for index, group_name in enumerate(group_names):
        if index == 0:
            continue
        group_path = "/".join(group_names[0: index + 1])
        group = get_group_by_name(realm=cxone_tenant_name, group_name=group_path)
        if not group:
            logger.info(f"current group: {group_path} does not exist, start create")
            create_subgroup(realm=cxone_tenant_name, group_id=parent_group_id, subgroup_name=group_name)
            logger.info(f"finish create group: {group_path}")
            group = get_group_by_name(realm=cxone_tenant_name, group_name=group_path)
        parent_group_id = group.id
    return parent_group_id


def create_root_group_if_not_exist(cxone_tenant_name, root_group_name) -> str:
    root_group = get_group_by_name(realm=cxone_tenant_name, group_name=root_group_name)
    if root_group:
        root_group_id = root_group.id
        logger.info(f"root group {root_group_name} exist. id: {root_group_id}")
    else:
        logger.info(f"root group not exist, start create root group")
        create_group(realm=cxone_tenant_name, group_name=root_group_name)
        root_group = get_group_by_name(realm=cxone_tenant_name, group_name=root_group_name)
        root_group_id = root_group.id
        logger.info(f"root group {root_group_name} created. id: {root_group_id}")
    return root_group_id


def process_project(
        project_data: dict,
        groups_data: List[dict] = None,
        sca_last_sast_scan_time: int = 2
) -> str:
    project_criticality = project_data.get("criticality")
    project_groups = project_data.get("groups")
    project_main_branch = project_data.get("mainBranch")
    project_name = project_data.get("name")
    project_origin = project_data.get("origin")
    project_repo_url = project_data.get("repoUrl")
    project_tags = project_data.get("tags")
    project_collection = get_a_list_of_projects(names=[project_name])
    if not project_collection.projects:
        logger.info("project does not exist. create project")
        project = create_a_project(
            project_input=ProjectInput(
                name=project_name,
                # groups=[
                #     list(
                #         filter(lambda r: r.get("name") == group_name, groups_data)
                #     )[0].get("id") for group_name in project_groups
                # ],
                repo_url=project_repo_url,
                main_branch=project_main_branch,
                origin=project_origin,
                tags=project_tags,
                criticality=project_criticality
            )
        )
        project_id = project.id
        logger.info(f"new project name {project_name} with project_id: {project_id} created.")
        logger.info(f"project id: {project_id}")
        logger.info("start update project configuration")
        scan_parameters = [
            ScanParameter(
                key="scan.config.sca.ExploitablePath",
                name="exploitablePath",
                category="sca",
                origin_level="Project",
                value="false",
                value_type="Bool",
                value_type_params=None,
                allow_override=True
            ),
            ScanParameter(
                key="scan.config.sca.LastSastScanTime",
                name="lastSastScanTime",
                category="sca",
                origin_level="Project",
                value=f"{sca_last_sast_scan_time}",
                value_type="Number",
                value_type_params=None,
                allow_override=True
            ),
        ]
        define_parameters_in_the_input_list_for_a_specific_project(
            project_id=project_id,
            scan_parameters=scan_parameters
        )
        logger.info("finish update project configuration")
        return project_id


def process_application(
        application_data: dict,
) -> str:
    application_criticality = application_data.get("criticality")
    application_description = application_data.get("description")
    application_name = application_data.get("name")
    application_rules = application_data.get("rules")
    application_tags = application_data.get("tags")
    application_collection = get_a_list_of_applications()
    filtered_applications = list(filter(lambda r: r.name == application_name, application_collection.applications))
    if not application_collection.applications or not filtered_applications:
        logger.info("application does not exist. create application")
        application_input = ApplicationInput(
            name=application_name,
            description=application_description,
            criticality=application_criticality,
            rules=[
                RuleInput(
                    rule_type=rule.get("type"),
                    value=rule.get("value"),
                ) for rule in application_rules
            ],
            tags=application_tags
        )
        application = create_an_application(application_input=application_input)
        logger.info(f"new application name {application_name} with application_id: {application.id} created.")

        return application.id


def process_groups_projects_applications(groups, projects, applications, cxone_tenant_name):
    for group in groups:
        try:
            group_id = get_or_create_groups(
                group_full_name=group.get("name"),
                cxone_tenant_name=cxone_tenant_name
            )
            group["id"] = group_id
        except Exception:
            add_failed_message(f"group_name: {group.get("name")}")
            continue
    for project in projects:
        try:
            process_project(
                project_data=project,
                # groups_data=groups,
                sca_last_sast_scan_time=2
            )
        except Exception:
            add_failed_message(f"project_name: {project.get("name")}")
            continue
    for application in applications:
        try:
            process_application(application)
        except Exception:
            add_failed_message(f"application_name: {application.get("name")}")
            continue


def add_failed_message(message):
    with open("failure.txt", "a") as file:
        file.write(message)


if __name__ == '__main__':
    with open('data.pkl', 'rb') as f:
        data = pickle.load(f)
    groups = data.get("groups")
    projects = data.get("projects")
    applications = data.get("applications")
    cxone_tenant_name = "coupangmst"
    groups_in_mt_tenant = get_groups(cxone_tenant_name)
    groups_not_created = []
    for group in groups:
        group_name = group.get("name")
        group_in_mt = list(filter(lambda r: r.name == group_name, groups_in_mt_tenant))
        if not group_in_mt:
            groups_not_created.append(group)
    process_groups_projects_applications(groups_not_created, projects, applications, cxone_tenant_name)
