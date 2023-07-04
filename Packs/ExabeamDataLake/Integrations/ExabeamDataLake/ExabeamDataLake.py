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

        if self.username != TOKEN_INPUT_IDENTIFIER:
            self._logout()
        super().__del__()

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
        self._http_request('GET', full_url=f'{self._base_url}/api/auth/check', resp_type='text')


""" COMMAND FUNCTIONS """


def query_datalake_command(self, start_time: int = None, query: str = None):
    """
    Args:
        query: query for search
        start_time: start time to search for logs
    Returns:
        logs
    """
    query = demisto.args().get("query")
    start_time = demisto.args().get("startTime")
    {
        "sort": [{"indexTime": "asc"}],
        "query": {
            "bool": {
                "filter": {
                    "bool": {"minimum_should_match": 1, "must_not": [], "should": []}
                },
                "must": {
                    "bool": {
                        "must_not": [],
                        "must": [
                            query,
                            {
                                "range": {
                                    "indexTime": {
                                        "gte": start_time * 1000,
                                        "format": "epoch_millis",
                                    }
                                }
                            },
                        ],
                    }
                },
            }
        },
    }
    headers = {"kbn-version": "5.1.1-SNAPSHOT", "Content-Type": "application/json"}

    params = {
        "size": 200,
        "sort": [{"indexTime": "asc"}],
        "query": {
            "bool": {
                "filter": {
                    "bool": {"minimum_should_match": 1, "must_not": [], "should": []}
                },
                "must": {
                    "bool": {
                        "must_not": [],
                        "must": [
                            query,
                            {
                                "range": {
                                    "indexTime": {
                                        "gte": start_time * 1000,
                                        "format": "epoch_millis",
                                    }
                                }
                            },
                        ],
                    }
                },
            }
        },
    }
    params2 = json.dumps(params)

    # response = requests.post(full_url, params=params, headers=headers, timeout=120, verify=False, json=search_query)

    response = self._http_request(
        "POST",
        full_url=f"{self._base_url}/dl/api/es/search",
        params=params2,
        headers=headers,
        timeout=120,
        resp_type="text",
    )

    if response != 200:
        error = response.status_code
        return error

    if response == 200:
        return response.json()["hits"]["hits"]
    return None

    # results = CommandResults(
    # outputs_prefix='ExabeamDatalake',
    # outputs_key_field="Logs",
    # outputs = response
    # )
    # return_results(results)


def test_module(client: Client):
    """test function

    Args:
        client: Client

    Returns:
        ok if successful
    """
    client.test_module_request()
    demisto.results('ok')


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    username = params.get("credentials", {}).get("identifier")
    password = params.get("credentials", {}).get("password")
    base_url = params["url"].rstrip('/')

    verify_certificate = not params.get("insecure", False)

    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {command}")
    headers = {'Accept': 'application/json', 'Csrf-Token': 'nocheck'}
    if username == TOKEN_INPUT_IDENTIFIER:
        headers["ExaAuthToken"] = password
    try:
        client = Client(base_url, verify=verify_certificate, username=username,
                        password=password, proxy=proxy, headers=headers)
        command = demisto.command()

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
