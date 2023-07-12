from datetime import date
import demistomock as demisto
from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
TOKEN_INPUT_IDENTIFIER = "__token"

""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client to use in the Exabeam DataLake integration. Overrides BaseClient
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool,
        proxy: bool,
        headers,
        api_key: str = "",
    ):
        super().__init__(
            base_url=f"{base_url}", headers=headers, verify=verify, proxy=proxy
        )
        self.username = username
        self.password = password
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers = headers
        if not proxy:
            self.session.trust_env = False
        if self.username != TOKEN_INPUT_IDENTIFIER:
            self._login()

        # if self.username != TOKEN_INPUT_IDENTIFIER:
        #     self._logout()
        # super().__del__()

    def _login(self):
        """
        Login using the credentials and store the cookie
        """
        self._http_request(
            "POST",
            full_url=f"{self._base_url}/api/auth/login",
            data={"username": self.username, "password": self.password},
        )

    def _logout(self):
        """
        Logout from the session
        """
        try:
            self._http_request("GET", full_url=f"{self._base_url}/api/auth/logout")
        except Exception as err:
            demisto.debug(f"An error occurred during the logout.\n{str(err)}")

    def test_module_request(self):
        """
        Performs basic get request to check if the server is reachable.
        """
        self._http_request(
            "GET", full_url=f"{self._base_url}/api/auth/check", resp_type="text"
        )

    def query_datalake_request(self, search_query: dict) -> dict:
        headers = {"kbn-version": "5.1.1-SNAPSHOT", "Content-Type": "application/json"}
        return self._http_request(
            "POST",
            full_url=f"{self._base_url}/dl/api/es/search",
            data=json.dumps(search_query),
            headers=headers,
        )


""" COMMAND FUNCTIONS """


def query_datalake_command(client: Client, args: dict) -> CommandResults:
    """
    Args:
        args: demisto.args()
    Returns:
        logs
    """
    query = args["query"]
    limit = arg_to_number(args.get("limit", 50))
    all_result = argToBoolean(args.get("all_result", False))

    if start_time := args.get("start_time"):
        start_time = date_to_timestamp(start_time)

    if end_time := args.get("end_time"):
        end_time = date_to_timestamp(end_time)

    if start_time > end_time:
        raise ValueError("Start time must be before end time")

    if all_result:
        size = "*"
    elif:
        size = limit

    search_query = {
        "sortBy": [{"field": "@timestamp", "order": "desc", "unmappedType": "date"}], # the response sort by timestamp
        "rangeQuery": { # get query start and end time
            "field": "@timestamp",
            "gte": str(start_time * 1000), # Greater than or equal to.
            "lte": str(end_time * 1000),  # Less than.
        },
        "query": query, # can be "VPN" or "*"
        "size": size, # the size of the response
        "clusterWithIndices": [
            {
                "clusterName": "local",
                "indices": ["exabeam-2023.07.12"],
            }  # TODO -need to check if this is hardcoded
        ],
    }

    response = client.query_datalake_request(search_query)

    response = response["responses"][0]["hits"]["hits"]
    markdown_table = tableToMarkdown("Logs", t=response)
    
    return CommandResults(
        outputs_prefix="ExabeamDataLake.Log",
        outputs=response,
        readable_output=markdown_table
    )


def test_module(client: Client):
    """test function

    Args:
        client: Client

    Returns:
        ok if successful
    """
    client.test_module_request()
    demisto.results("ok")


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    username = params["credentials"]["identifier"]
    password = params["credentials"]["password"]
    base_url = params["url"].rstrip("/")

    verify_certificate = not params.get("insecure", False)

    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    headers = {"Accept": "application/json", "Csrf-Token": "nocheck"}

    if username == TOKEN_INPUT_IDENTIFIER:
        headers["ExaAuthToken"] = password
    try:
        client = Client(
            base_url,
            verify=verify_certificate,
            username=username,
            password=password,
            proxy=proxy,
            headers=headers,
        )

        match command:
            case "test-module":
                return_results(test_module(client))
            case "exabeam-data-lake-query":
                return_results(query_datalake_command(client, args))
            case _:
                raise NotImplementedError(f"Command {command} is not supported")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
