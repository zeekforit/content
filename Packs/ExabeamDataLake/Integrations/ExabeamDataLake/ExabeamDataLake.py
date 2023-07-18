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
    Query the datalake command and return the results in a formatted table.

    Args:
        client: The client object for interacting with the API.
        args: The arguments passed to the command.

    Returns:
        CommandResults: The command results object containing outputs and readable output.
    """
    def _parse_entry(entry: dict) -> dict:
        """
        Parse a single entry from the API response to a dictionary.

        Args:
            entry: The entry from the API response.

        Returns:
            dict: The parsed entry dictionary.
        """
        source = entry["_source"]
        return {
            "id": entry.get("_id"),
            "Vendor": source.get("Vendor"),
            "time": source.get("time"),
            "Product": source.get("Product"),
            "event name": source.get("event_name"),
            "action": source.get("action"),
        }

    query = args["query"]
    limit = arg_to_number(args.get("limit", 50))
    all_result = argToBoolean(args.get("all_result", False))

    search_query: dict = {}

    if start_time := args.get("start_time"):
        search_query["rangeQuery"] = {"field": "@timestamp"}
        search_query["rangeQuery"].update(
            {"gte": str(date_to_timestamp(start_time))}
        )

    if (end_time := args.get("end_time")) and not start_time:
        raise ValueError("Start time must be provided with end time")

    search_query["rangeQuery"].update(
        {"lte": str(date_to_timestamp(end_time))}
    )

    if start_time and start_time > end_time:
        raise ValueError("Start time must be before end time")

    result_size_to_get = 10_000 if all_result else limit

    search_query.update(
        {
            "sortBy": [
                {"field": "@timestamp", "order": "desc", "unmappedType": "date"}
            ],  # the response sort by timestamp
            "query": query,  # can be "VPN" or "*"
            "size": result_size_to_get,  # the size of the response
            "clusterWithIndices": [
                {
                    "clusterName": "local",
                    "indices": ["exabeam-2023.07.12"],
                }  # TODO -need to check if this is hardcoded
            ],
        }
    )

    response = client.query_datalake_request(search_query)
    if error := response["responses"][0].get("error"):
        raise DemistoException(f"Error in query: {error['root_cause'][0]['reason']}")

    data_response = response["responses"][0]["hits"]["hits"]
    table_to_markdown = [_parse_entry(entry) for entry in data_response]
    markdown_table = tableToMarkdown(name="Logs", t=table_to_markdown)

    return CommandResults(
        outputs_prefix="ExabeamDataLake.Log",
        outputs=data_response,
        readable_output=markdown_table,
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
