import base64
import contextlib
import glob
import json
import os
import re
import sys
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import demisto_client
import humanize  # noqa
from demisto_sdk.commands.common import tools
from demisto_sdk.commands.content_graph.common import PACK_METADATA_FILENAME
from google.cloud.storage import Bucket  # noqa type: ignore
from packaging.version import Version
from requests import Session

from Tests.Marketplace.common import ALREADY_IN_PROGRESS, generic_request_with_retries, wait_until_not_updating
from Tests.Marketplace.marketplace_constants import (
    IGNORED_FILES,
    PACKS_FOLDER,
    PACKS_FULL_PATH,
    GCPConfig,
)
from Tests.Marketplace.marketplace_services import Pack, init_storage_client
from Tests.scripts.utils import logging_wrapper as logging

PACK_PATH_VERSION_REGEX = re.compile(
    rf"^{GCPConfig.PRODUCTION_STORAGE_BASE_PATH}/[A-Za-z0-9-_.]+/(\d+\.\d+\.\d+)/[A-Za-z0-9-_.]"
    r"+\.zip$"
)
WLM_TASK_FAILED_ERROR_CODE = 101704

GITLAB_SESSION = Session()
CONTENT_PROJECT_ID = "2596"
PACKS_DIR = "Packs"
PACK_METADATA_FILE = Pack.USER_METADATA
MAX_WORKERS = 130
GITLAB_PACK_METADATA_URL = (
    f"{{gitlab_url}}/api/v4/projects/{CONTENT_PROJECT_ID}/repository/files/{PACKS_DIR}%2F{{pack_id}}%2F"
    f"{PACK_METADATA_FILE}"
)

MALFORMED_PACK_PATTERN = re.compile(
    r"invalid version [0-9.]+ for pack with ID ([\w_-]+)"
)

PackIdVersion = namedtuple('PackIdVersion', ['id', 'version'])


@lru_cache
def get_env_var(var_name: str) -> str:
    """
    Get an environment variable.
    This method adds a cache layer to the 'os.getenv' method, and raises an error if the variable is not set.

    Args:
        var_name (str): Name of the environment variable to get.

    Returns:
        str: Value of the environment variable.
    """
    var_value = os.getenv(var_name)
    if not var_value:
        raise ValueError(f"Environment variable '{var_name}' is not set.")

    return var_value


@lru_cache(maxsize=128)
def fetch_pack_metadata_from_gitlab(pack_id: str, commit_hash: str) -> dict:
    """
    Fetch pack metadata from master (a commit hash of the master branch when the build was triggered) using GitLab's API.

    Args:
        pack_id (str): ID of the pack to fetch metadata for (name of Pack's folder).
        commit_hash (str): A commit hash to fetch the metadata file from.

    Returns:
        dict: A dictionary containing pack's metadata.
    """
    api_url = GITLAB_PACK_METADATA_URL.format(
        gitlab_url=get_env_var("CI_SERVER_URL"), pack_id=pack_id
    )
    logging.debug(
        f"Fetching 'pack_metadata.json' file from GitLab for pack '{pack_id}'..."
    )
    response = GITLAB_SESSION.get(
        api_url,
        headers={"PRIVATE-TOKEN": get_env_var("GITLAB_API_READ_TOKEN")},
        params={"ref": commit_hash},
    )

    if response.status_code != 200:
        logging.error(
            f"Failed to fetch pack metadata from GitLab for pack '{pack_id}'.\n"
            f"Response code: {response.status_code}\nResponse body: {response.text}"
        )
        response.raise_for_status()

    file_data_b64 = response.json()["content"]
    file_data = base64.b64decode(file_data_b64).decode("utf-8")

    return json.loads(file_data)


def is_pack_deprecated(
    pack_id: str,
    production_bucket: bool = True,
    commit_hash: str | None = None,
    pack_api_data: dict | None = None,
) -> bool:
    """
    Check whether a pack is deprecated or not.
    If an error is encountered, and status can't be checked properly,
    the deprecation status will be set to a default value of False.

    Note:
        If 'production_bucket' is True, one of 'master_commit_hash' or 'pack_api_data' must be provided
        in order to determine whether the pack is deprecated or not.
        'commit_hash' is used to fetch pack's metadata from a specific commit hash (ex: production bucket's last commit)
        'pack_api_data' is the API data of a specific pack item (and not the complete response with a list of packs).

    Args:
        pack_id (str): ID of the pack to check.
        production_bucket (bool): Whether we want to check deprecation status on production bucket.
            Otherwise, deprecation status will be determined by checking the local 'pack_metadata.json' file.
        commit_hash (str, optional): Commit hash branch to use if 'production_bucket' is False.
            If 'pack_api_data' is not provided, will be used for fetching 'pack_metadata.json' file from GitLab.
        pack_api_data (dict | None, optional): Marketplace API data to use if 'production_bucket' is False.
            Needs to be the API data of a specific pack item (and not the complete response with a list of packs).

    Returns:
        bool: True if the pack is deprecated, False otherwise
    """
    if production_bucket:
        if pack_api_data:
            try:
                return pack_api_data["extras"]["pack"].get("deprecated", False)

            except Exception as ex:
                logging.error(
                    f"Failed to parse API response data for '{pack_id}'.\n"
                    f"API Data: {pack_api_data}\nError: {ex}"
                )

        elif commit_hash:
            try:
                return fetch_pack_metadata_from_gitlab(
                    pack_id=pack_id, commit_hash=commit_hash
                ).get("hidden", False)

            except Exception as ex:
                logging.error(
                    f"Failed to fetch pack metadata from GitLab for pack '{pack_id}'.\nError: {ex}"
                )

        else:
            raise ValueError(
                "Either 'master_commit_hash' or 'pack_api_data' must be provided."
            )

    else:  # Check locally
        pack_metadata_path = Path(PACKS_FOLDER) / pack_id / PACK_METADATA_FILENAME

        if pack_metadata_path.is_file():
            try:
                return tools.get_pack_metadata(str(pack_metadata_path)).get(
                    "hidden", False
                )

            except Exception as ex:
                logging.error(
                    f"Failed to open file '{pack_metadata_path}'.\nError: {ex}"
                )

        else:
            logging.warning(
                f"File '{pack_metadata_path}' could not be found, or isn't a file."
            )

    # If we got here, it means that nothing was returned and an error was encountered
    logging.warning(
        f"Deprecation status of '{pack_id}' could not be determined, "
        "and has been set to a default value of 'False'.\n"
        "Note that this might result in potential errors if it is deprecated."
    )
    return False


def get_latest_version_from_bucket(pack_id: str, production_bucket: Bucket) -> str:
    """
    Retrieves the latest version of pack in a production bucket

    Args:
        pack_id (str): The pack id to retrieve the latest version
        production_bucket (Bucket): The GCS production bucket

    Returns:
        The latest version of the pack as it is in the production bucket
    """
    pack_bucket_path = os.path.join(GCPConfig.PRODUCTION_STORAGE_BASE_PATH, pack_id)
    logging.debug(
        f"Trying to get the latest version of pack {pack_id} from bucket path {pack_bucket_path}"
    )
    # Adding the '/' in the end of the prefix to search for the exact pack id
    pack_versions_paths = [
        f.name
        for f in production_bucket.list_blobs(prefix=f"{pack_bucket_path}/")
        if f.name.endswith(".zip")
    ]

    pack_versions = []
    for path in pack_versions_paths:
        versions = PACK_PATH_VERSION_REGEX.findall(path)
        if not versions:
            continue
        pack_versions.append(Version(versions[0]))

    logging.debug(f"Found the following versions for pack {pack_id}: {pack_versions}")
    if pack_versions:
        return str(max(pack_versions))
    logging.error(
        f"Could not find any versions for pack {pack_id} in bucket path {pack_bucket_path}"
    )
    return ""


def get_pack_installation_request_data(pack_id: str, pack_version: str):
    """
    Returns the installation request data of a given pack and its version. The request must have the ID and Version.

    :param pack_id: ID of the pack to add.
    :param pack_version: Version of the pack to add.
    :return: The request data part of the pack
    """
    return {"id": pack_id, "version": pack_version}


def install_all_content_packs_for_nightly(
    client: demisto_client, host: str, service_account: str
):
    """Iterates over the packs currently located in the Packs directory. Wrapper for install_packs.
    Retrieving the latest version of each pack from the production bucket.

    :param client: Demisto-py client to connect to the server.
    :param host: FQDN of the server.
    :param service_account: The full path to the service account json.
    :return: None. Prints the response from the server in the build.
    """
    all_packs = []

    # Initiate the GCS client and get the production bucket
    storage_client = init_storage_client(service_account)
    production_bucket = storage_client.bucket(GCPConfig.PRODUCTION_BUCKET)
    logging.debug(f"Installing all content packs for nightly flow in server {host}")

    # Add deprecated packs to IGNORED_FILES list:
    for pack_id in os.listdir(PACKS_FULL_PATH):
        if is_pack_deprecated(pack_id=pack_id, production_bucket=False):
            logging.debug(f'Skipping installation of deprecated pack "{pack_id}"')
            IGNORED_FILES.append(pack_id)

    for pack_id in os.listdir(PACKS_FULL_PATH):
        if pack_id not in IGNORED_FILES:
            pack_version = get_latest_version_from_bucket(pack_id, production_bucket)
            if pack_version:
                all_packs.append(
                    get_pack_installation_request_data(pack_id, pack_version)
                )
                logging.debug(f'Skipping installation of ignored pack "{pack_id}"')
    install_packs(client, all_packs)


# def install_all_content_packs_from_build_bucket(
#     client: demisto_client,
#     host: str,
#     server_version: str,
#     bucket_packs_root_path: str,
#     service_account: str,
#     extract_destination_path: str,
# ):
#     """Iterates over the packs currently located in the Build bucket. Wrapper for install_packs.
#     Retrieving the metadata of the latest version of each pack from the index.zip of the build bucket.
#
#     :param client: Demisto-py client to connect to the server.
#     :param host: FQDN of the server.
#     :param server_version: The version of the server the packs are installed on.
#     :param bucket_packs_root_path: The prefix to the root of packs in the bucket
#     :param service_account: Google Service Account
#     :param extract_destination_path: the full path of extract folder for the index.
#     :return: None. Prints the response from the server in the log.
#     """
#     all_packs = []
#     logging.debug(
#         f"Installing all content packs in server {host} from packs path {bucket_packs_root_path}"
#     )
#
#     storage_client = init_storage_client(service_account)
#     build_bucket = storage_client.bucket(GCPConfig.CI_BUILD_BUCKET)
#     index_folder_path, _, _ = download_and_extract_index(
#         build_bucket, extract_destination_path, bucket_packs_root_path
#     )
#
#     for pack_id in os.listdir(index_folder_path):
#         if Path(os.path.join(index_folder_path, pack_id)).is_dir():
#             metadata_path = os.path.join(index_folder_path, pack_id, Pack.METADATA)
#             pack_metadata = load_json(metadata_path)
#             if "partnerId" in pack_metadata:  # not installing private packs
#                 logging.debug(f'Skipping installation of partner pack "{pack_id}"')
#                 continue
#             pack_version = pack_metadata.get(
#                 Metadata.CURRENT_VERSION, Metadata.SERVER_DEFAULT_MIN_VERSION
#             )
#             server_min_version = pack_metadata.get(
#                 Metadata.SERVER_MIN_VERSION, Metadata.SERVER_DEFAULT_MIN_VERSION
#             )
#             hidden = pack_metadata.get(Metadata.HIDDEN, False)
#             # Check if the server version is greater than the minimum server version required for this pack or if the
#             # pack is hidden (deprecated):
#             if (
#                 "master" in server_version.lower()
#                 or Version(server_version) >= Version(server_min_version)
#             ) and not hidden:
#                 logging.debug(f"Appending pack id {pack_id} to the list of packs to install")
#                 all_packs.append(
#                     get_pack_installation_request_data(pack_id, pack_version)
#                 )
#             else:
#                 reason = (
#                     "Is hidden"
#                     if hidden
#                     else f"min server version is {server_min_version} and server version is {server_version}"
#                 )
#                 logging.debug(
#                     f"Pack: {pack_id} with version: {pack_version} will not be installed on {host}. "
#                     f"Pack {reason}."
#                 )
#     return install_packs(client, host, all_packs)


def upload_zipped_packs(client: demisto_client, host: str, pack_path: str):
    """
    Install packs from zip file.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        pack_path (str): path to pack zip.
    """
    header_params = {"Content-Type": "multipart/form-data"}
    auth_settings = ["api_key", "csrf_token", "x-xdr-auth-id"]
    file_path = str(Path(pack_path).resolve())
    files = {"file": file_path}

    logging.info(
        f'Making "POST" request to server {host} - to install all packs from file {pack_path}'
    )

    # make the pack installation request
    try:
        response_data, status_code, _ = client.api_client.call_api(
            resource_path="/contentpacks/installed/upload",
            method="POST",
            auth_settings=auth_settings,
            header_params=header_params,
            files=files,
            response_type="object",
        )

        if 200 <= status_code < 300 and status_code != 204:
            logging.info(
                f"All packs from file {pack_path} were successfully installed on server {host}"
            )
        else:
            message = response_data.get("message", "")
            raise Exception(
                f"Failed to install packs from file {pack_path} with status code {status_code}\n{message}"
            )
    except Exception:  # noqa E722
        logging.exception("The request to install packs from file {pack_path} has failed. Exiting.")
        sys.exit(1)


def search_and_install_packs_and_their_dependencies_private(
    test_pack_path: str, pack_ids: list, client: demisto_client
):
    """Searches for the packs from the specified list, searches their dependencies, and then installs them.
    Args:
        test_pack_path (str): Path of where the test packs are located.
        pack_ids (list): A list of the pack ids to search and install.
        client (demisto_client): The client to connect to.

    Returns (list, bool):
        A list of the installed packs' ids, or an empty list if is_nightly == True.
        A flag that indicates if the operation succeeded or not.
    """
    host = client.api_client.configuration.host

    logging.info(f"Starting to search and install packs in server: {host}")

    return install_packs_private(client, host, pack_ids, test_pack_path)


def get_pack_id_from_error_with_gcp_path(error: str) -> str:
    """
    Gets the id of the pack from the pack's path in GCP that is mentioned in the error msg.

    Returns:
        str: The id of given pack.
    """
    return error.split("/packs/")[1].split(".zip")[0].split("/")[0]


def install_packs_private(
    client: demisto_client, host: str, pack_ids_to_install: list, test_pack_path: str
) -> bool:
    """Make a packs installation request.

    Args:
        client (demisto_client): The configured client to use.
        host (str): The server URL.
        pack_ids_to_install (list): List of Pack IDs to install.
        test_pack_path (str): Path where test packs are located.
    Returns:
        bool: True if the packs were installed successfully, False otherwise.
    """
    return install_packs_from_artifacts(
        client,
        host,
        pack_ids_to_install=pack_ids_to_install,
        test_pack_path=test_pack_path,
    )


def find_malformed_pack_id(body: str) -> list:
    """
    Find the pack ID from the installation error message in the case the error is that the pack is not found or
    in case that the error is that the pack's version is invalid.
    Args:
        body (str): The response message of the failed installation pack.

    Returns: list of malformed ids (list)

    """
    malformed_ids = []
    if body:
        with contextlib.suppress(json.JSONDecodeError):
            response_info = json.loads(body)
            if error_info := response_info.get("error"):
                errors_info = [error_info]
            else:
                # the errors are returned as a list of error
                errors_info = response_info.get("errors", [])
            for error in errors_info:
                if "pack id: " in error:
                    malformed_ids.extend(
                        error.split("pack id: ")[1]
                        .replace("]", "")
                        .replace("[", "")
                        .replace(" ", "")
                        .split(",")
                    )
                else:
                    malformed_pack_id = MALFORMED_PACK_PATTERN.findall(str(error))
                    if malformed_pack_id and error:
                        malformed_ids.extend(malformed_pack_id)
    return malformed_ids


def handle_malformed_pack_ids(malformed_pack_ids, packs_to_install):
    """
    Handles the case where the malformed id failed the installation, but it was not a part of the initial installation.
    This is in order to prevent an infinite loop for this such edge case.
    Args:
        malformed_pack_ids: the ids found from the error msg
        packs_to_install: list of packs that was already installed that caused the failure.

    Returns:
        raises an error.
    """
    for malformed_pack_id in malformed_pack_ids:
        if malformed_pack_id not in {pack["id"] for pack in packs_to_install}:
            raise Exception(
                f"The pack {malformed_pack_id} has failed to install even "
                f"though it was not in the installation list"
            )


def install_packs_from_artifacts(
    client: demisto_client, host: str, test_pack_path: str, pack_ids_to_install: list
) -> bool:
    """
    Installs all the packs located in the artifacts folder of the GitHub actions build. Please note:
    The server always returns a 200 status even if the pack was not installed.

    :param client: Demisto-py client to connect to the server.
    :param host: FQDN of the server.
    :param test_pack_path: Path to the test pack directory.
    :param pack_ids_to_install: List of pack IDs to install.
    :return: book. Call to server waits until a successful response.
    """
    logging.info(f"Test pack path is: {test_pack_path}")
    logging.info(f"Pack IDs to install are: {pack_ids_to_install}")

    local_packs = glob.glob(f"{test_pack_path}/*.zip")

    for local_pack in local_packs:
        if any(pack_id in local_pack for pack_id in pack_ids_to_install):
            logging.info(f"Installing the following pack: {local_pack}")
            upload_zipped_packs(client=client, host=host, pack_path=local_pack)
    return True


def get_error_ids(body: str) -> dict[int, str]:
    with contextlib.suppress(json.JSONDecodeError):
        response_info = json.loads(body)
        return {error["id"]: error.get("details", "") for error in response_info.get("errors", []) if "id" in error}
    return {}


def install_packs(
    client: demisto_client,
    packs_to_install: list,
    request_timeout: int = 3600,
    attempts_count: int = 5,
    sleep_interval: int = 60,
) -> tuple[bool, list[dict]]:
    """Make a packs installation request.
       If a pack fails to install due to malformed pack, this function catches the corrupted pack and call another
       request to install packs again, this time without the corrupted pack.
       If a pack fails to install due to timeout when sending a request to GCP,
       request to install all packs again once more.

    Args:
        client (demisto_client): The configured client to use.
        packs_to_install (list): A list of the packs to install.
        request_timeout (int): Timeout setting, in seconds, for the installation request.
        attempts_count (int): The number of attempts to install the packs.
        sleep_interval (int): The sleep interval, in seconds, between install attempts.
    Returns:
        tuple[bool, list[dict]]: Success status and a list of the installed packs' data.
    """

    def success_handler(response):
        nonlocal packs_to_install
        packs_data = [
            {
                "ID": pack.get("id"),
                "CurrentVersion": pack.get("currentVersion"),
            }
            for pack in response
        ]
        logging.success(
            "packs that were successfully installed on server:"
        )
        for pack in packs_data:
            logging.debug(f"\tID:{pack['ID']} Version:{pack['CurrentVersion']}")
        return True, packs_data

    def api_exception_handler(ex, attempts_left):
        nonlocal packs_to_install
        if ALREADY_IN_PROGRESS in ex.body:
            wait_succeeded = wait_until_not_updating(client)
            if not wait_succeeded:
                raise Exception(
                    "Failed to wait for the server to exit installation/updating status"
                ) from ex
            return

        if malformed_ids := find_malformed_pack_id(ex.body):
            handle_malformed_pack_ids(malformed_ids, packs_to_install)
            if not attempts_left:
                raise Exception(f"malformed packs: {malformed_ids}") from ex

            # We've more attempts, retrying without tho malformed packs.
            logging.error(f"Unable to install malformed packs: {malformed_ids}, retrying without them.")
            packs_to_install = [pack for pack in packs_to_install if pack['id'] not in malformed_ids]

        error_ids = get_error_ids(ex.body)
        if WLM_TASK_FAILED_ERROR_CODE in error_ids:
            if "polling request failed for task ID" in error_ids[WLM_TASK_FAILED_ERROR_CODE].lower():
                logging.error(f"Got {WLM_TASK_FAILED_ERROR_CODE} error code - polling request failed for task ID, "
                              f"retrying.")
            else:
                # If we got this error code, it means that the modeling rules are not valid, exiting install flow.
                raise Exception(f"Got [{WLM_TASK_FAILED_ERROR_CODE}] error code - Modeling rules and Dataset validations "
                                f"failed. Please look at GCP logs to understand why it failed.") from ex

        if not attempts_left:  # exhausted all attempts, understand what happened and exit.
            if 'timeout awaiting response' in ex.body:
                if '/packs/' in ex.body:
                    pack_id = get_pack_id_from_error_with_gcp_path(ex.body)
                    raise Exception(
                        f"timeout awaiting response headers while trying to install pack {pack_id}"
                    ) from ex

                raise Exception(
                    "timeout awaiting response headers while trying to install, "
                    "couldn't determine pack id."
                ) from ex

            if "item not found" in ex.body.lower():
                raise Exception(
                    f"Item not found error, headers:{ex.headers}."
                ) from ex

    if not packs_to_install:
        logging.info(
            "There are no packs to install on server. Consolidating installation as success"
        )
        return True, []

    packs_list = ','.join([p['id'] for p in packs_to_install])
    failure_massage = f'Failed to install packs: {packs_list}'

    return generic_request_with_retries(client=client,
                                        retries_message=failure_massage,
                                        exception_message=failure_massage,
                                        prior_message="Installing packs...",
                                        path="/contentpacks/marketplace/install",
                                        body={"packs": packs_to_install, "ignoreWarnings": True},
                                        method="POST",
                                        response_type="object",
                                        attempts_count=attempts_count,
                                        sleep_interval=sleep_interval,
                                        request_timeout=request_timeout,
                                        success_handler=success_handler,
                                        api_exception_handler=api_exception_handler)


def create_dependencies_data_structure(
    response_data: dict, dependants_ids: list, checked_packs: list
):
    """
    Recursively create packs' dependencies data structure for installation requests (only required and uninstalled).

    Args:
        response_data (dict): Dependencies data from the '/search/dependencies' endpoint response.
        dependants_ids (list): A list of the dependant packs IDs.
        checked_packs (list): Required dependants that were already found.
    """
    next_call_dependants_ids: list = []
    dependencies_data: list = []
    for dependency in response_data:
        dependants = dependency.get("dependants", {})

        for dependant in dependants:
            if (
                dependants[dependant].get("level", "") == "required"
                and dependency["id"] not in checked_packs
                and dependant in dependants_ids
            ):
                dependencies_data.append(dependency)
                next_call_dependants_ids.append(dependency["id"])
                checked_packs.append(dependency["id"])

    if next_call_dependants_ids:
        dependencies_data.extend(
            create_dependencies_data_structure(
                response_data, next_call_dependants_ids, checked_packs
            )
        )
    return dependencies_data


def get_pack_dependencies(
    client: demisto_client,
    pack_id: str,
    attempts_count: int = 5,
    sleep_interval: int = 60,
    request_timeout: int = 300,
) -> dict | None:
    """
    Get pack's required dependencies.

    Args:
        client (demisto_client): The configured client to use.
        pack_id (str): ID of the pack to get dependencies for.
        attempts_count (int): The number of attempts to install the packs.
        sleep_interval (int): The sleep interval, in seconds, between request retry attempts.
        request_timeout (int): Timeout setting, in seconds, for the installation request.

    Returns:
        dict | None: API response data for the /search/dependencies endpoint. None if the request failed.
    """

    def success_handler(response):
        logging.debug(
            f"Successfully fetched dependencies for pack '{pack_id}'.\nResponse: '{json.dumps(response)}'"
        )
        return response

    failure_massage = f'Failed to search dependencies for pack: {pack_id}'
    prior_message = f"Searching dependencies information for '{pack_id}' using Marketplace API"
    return generic_request_with_retries(client=client,
                                        retries_message=failure_massage,
                                        exception_message=failure_massage,
                                        prior_message=prior_message,
                                        path="/contentpacks/marketplace/search/dependencies",
                                        method='POST',
                                        body=[
                                            {"id": pack_id}
                                        ],  # Not specifying a "version" key will return the latest version of the pack.
                                        response_type="object",
                                        attempts_count=attempts_count,
                                        sleep_interval=sleep_interval,
                                        success_handler=success_handler,
                                        request_timeout=request_timeout)


def get_pack_and_its_dependencies(
    client: demisto_client,
    pack_id: str,
    production_bucket: bool,
    commit_hash: str,
) -> tuple[str, bool, list[dict]]:
    """
    Update 'packs_to_install' (a pointer to a list that's reused and updated by the function on every iteration)
    with 'pack_id' and its dependencies, if 'pack_id' is not deprecated.
    The way deprecation status is determined depends on the 'production_bucket' flag.

    If 'production_bucket' is True, deprecation status is determined by checking the 'pack_metadata.json' file
    in the commit hash that was used for the last upload. If it's False, the deprecation status is checking the
    'pack_metadata.json' file locally (with changes applied on the branch).

    Args:
        client (demisto_client): The configured client to use.
        pack_id (str): The id of the pack to be installed.
        production_bucket (bool): Whether pack deprecation status  is determined using production bucket.
        commit_hash (str): Commit hash to use for checking pack's deprecations status if GitLab's API is used.
            If 'pack_api_data' is not provided, will be used for fetching 'pack_metadata.json' file from GitLab.
    Returns:
        tuple[str, bool, list[dict]]: A tuple of the pack id, whether it's deprecated, and its dependencies.
    """
    if is_pack_deprecated(
        pack_id=pack_id, production_bucket=production_bucket, commit_hash=commit_hash
    ):
        logging.warning(
            f"Pack '{pack_id}' is deprecated (hidden) and will not be installed."
        )
        return pack_id, True, []  # Don't install deprecated packs

    api_data = get_pack_dependencies(client=client, pack_id=pack_id)

    if not api_data:  # No dependencies were found for the pack.
        return pack_id, False, []

    dependencies_data: list[dict] = create_dependencies_data_structure(
        response_data=api_data.get("dependencies", []),
        dependants_ids=[pack_id],
        checked_packs=[pack_id],
    )
    pack_api_data = api_data["packs"][0]
    current_packs_to_install = [pack_api_data]

    if dependencies_data:
        logging.debug(
            f"Found dependencies for '{pack_id}': {[dependency['id'] for dependency in dependencies_data]}"
        )

        deprecated_dependencies = []
        for dependency in dependencies_data:
            if is_pack_deprecated(
                pack_id=dependency["id"],
                production_bucket=production_bucket,
                pack_api_data=dependency,
            ):
                deprecated_dependencies.append(dependency["id"])
            else:
                current_packs_to_install.append(dependency)
        if deprecated_dependencies:
            logging.warning(
                f"Pack '{pack_id}' has the following deprecated dependencies: {deprecated_dependencies}. "
                f"Will not install pack."
            )
            return pack_id, True, []

    dependencies = [
        get_pack_installation_request_data(
            pack_id=pack["id"],
            pack_version=pack["extras"]["pack"]["currentVersion"],
        )
        for pack in current_packs_to_install
    ]
    return pack_id, False, dependencies


def flatten_dependencies(pack_id: str,
                         pack_dependencies: list[dict],
                         all_packs_dependencies: dict[str, list[dict]],
                         recursion_packs_list: set[str] = None
                         ) -> list[dict]:
    """
    Flattens the dependencies of a pack recursively.
    Args:
        recursion_packs_list: A list of the packs that were already flattened.
        pack_id: pack_id to flatten dependencies for.
        pack_dependencies: pack_dependencies to flatten.
        all_packs_dependencies: all_packs_dependencies to use for flattening.

    Returns:
        list[dict]: A list of the flattened dependencies.
    """
    recursion_packs_list = recursion_packs_list or {pack_id}

    dependencies_flatten = {}  # Using a dict to avoid duplicates.
    for pack_dependency in pack_dependencies:
        if pack_dependency["id"] != pack_id and pack_dependency["id"] not in recursion_packs_list:
            recursion_packs_list.add(pack_dependency["id"])
            result = flatten_dependencies(
                pack_dependency["id"],
                all_packs_dependencies.get(pack_dependency["id"], []),
                all_packs_dependencies,
                recursion_packs_list,
            )
            for dependency in result:
                recursion_packs_list.add(dependency["id"])
                dependencies_flatten[dependency["id"]] = dependency

        dependencies_flatten[pack_dependency["id"]] = pack_dependency
    return list(dependencies_flatten.values())


def search_and_install_packs_and_their_dependencies(
    pack_ids: list,
    client: demisto_client,
    hostname: str | None = None,
    production_bucket: bool = True,
    multithreading=False,
    max_packs_to_install: int = 20,
) -> tuple[set[PackIdVersion], bool]:
    """
    Searches for the packs from the specified list, searches their dependencies, and then
    installs them.

    Args:
        multithreading(bool): Either to run the search process with multiple threads.
        max_packs_to_install (int): The maximum number of packs to install in one iteration.
        pack_ids (list): A list of the pack ids to search and install.
        client (demisto_client): The client to connect to.
        hostname (str): Hostname of instance. Using for logs.
        production_bucket (bool): Whether the installation is in post update mode. Defaults to False.
    Returns (list, bool):
        A list of the installed packs' ids and version.
        A flag that indicates if the operation succeeded or not.
    """
    host = hostname or client.api_client.configuration.host
    commit_hash: str = get_env_var("LAST_UPLOAD_COMMIT")

    logging.info(f"Starting to search and install packs on server {host}")
    start_time = datetime.utcnow()
    success = True
    all_packs_dependencies = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS if multithreading else 1, thread_name_prefix='SearchPacks') as pool:
        futures = [
            pool.submit(
                get_pack_and_its_dependencies,
                pack_id=pack_id,
                client=client,
                production_bucket=production_bucket,
                commit_hash=commit_hash,
            )
            for pack_id in pack_ids
        ]

        for future in as_completed(futures):
            try:
                pack_id, deprecated, dependencies_for_packs = future.result()
                if deprecated:
                    logging.error(
                        f"Pack '{pack_id}' is deprecated (hidden) and will not be installed."
                    )
                else:
                    all_packs_dependencies[pack_id] = dependencies_for_packs
            except Exception:  # noqa E722
                logging.exception(
                    f"An exception occurred while searching for dependencies of pack '{pack_ids[futures.index(future)]}'"
                )
                success = False

    if not success:
        logging.critical(
            "Failure while searching for packs dependencies, installing packs regardless."
        )

    logging.debug(f"Gathering all dependencies from:{len(all_packs_dependencies)} packs")
    distinct_packs_list: set[PackIdVersion] = set()
    for i, (pack_id, pack_dependencies) in enumerate(all_packs_dependencies.items(), start=1):
        logging.debug(f"[{i}/{len(all_packs_dependencies)}] Found dependencies for pack '{pack_id}':")
        logging.debug("Direct Dependencies:")
        for pack in pack_dependencies:
            logging.debug(f"\tID:{pack['id']} Version:{pack['version']}")
        packs = flatten_dependencies(pack_id, pack_dependencies, all_packs_dependencies)
        logging.debug("Flattened dependencies:")
        for pack in packs:
            distinct_packs_list.add(PackIdVersion(pack["id"], pack["version"]))
            logging.debug(f"\tID:{pack['id']} Version:{pack['version']}")
    logging.debug(f"Finished Gathering packs dependencies, found:{len(distinct_packs_list)} packs with their dependencies")

    logging.info("Starting to install packs")
    # Gather all dependencies and install them in batches.
    packs_installed_successfully: set[PackIdVersion] = set()
    packs_to_install: set[PackIdVersion] = set()
    failed_to_install_packs: set[PackIdVersion] = set()
    batch_number = 1
    for i, (pack_id, pack_dependencies) in enumerate(all_packs_dependencies.items()):
        packs = flatten_dependencies(pack_id, pack_dependencies, all_packs_dependencies)

        for pack in packs:
            pack_version = PackIdVersion(pack["id"], pack["version"])
            if pack_version not in packs_installed_successfully and pack_version not in failed_to_install_packs:
                packs_to_install.add(pack_version)

        if (
            len(packs_to_install) >= max_packs_to_install  # Reached max packs to install
            or i == len(all_packs_dependencies) - 1  # Last iteration
        ):
            logging.debug(f"Batch:{batch_number} - Installing {len(packs_to_install)} packs")
            batch_number += 1
            for pack_to_install in packs_to_install:
                logging.debug(f"\tID:{pack_to_install.id} Version:{pack_to_install.version}")

            success, installed_packs = install_packs(client, [{"id": pack_map.id,
                                                               "version": pack_map.version} for pack_map in packs_to_install])
            if success:
                packs_installed_successfully |= {
                    PackIdVersion(installed_pack["ID"], installed_pack["CurrentVersion"]) for installed_pack in installed_packs
                }
            else:
                failed_to_install_packs |= set(packs_to_install)
                success = False
            packs_to_install = set()  # Reset the batch of packs to install.

    duration = humanize.naturaldelta(datetime.utcnow() - start_time, minimum_unit='milliseconds')
    if success:
        logging.info(f"Installation of packs on {host} took {duration} - Finished successfully")
    else:
        logging.critical(f"Installation of packs on {host} took {duration} - Finished with errors, "
                         f"failed to install packs:")
        for failed_pack in failed_to_install_packs:
            logging.critical(f"\tID:{failed_pack.id} Version:{failed_pack.version}")

    return packs_installed_successfully, success
