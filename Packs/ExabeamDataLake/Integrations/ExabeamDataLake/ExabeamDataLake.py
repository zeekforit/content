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

    def query_datalake_request(
        self, query: str, start_time: int, end_time: int, limit: int, all_result: bool
    ):
        """
        Args:
            query: query to search
            start_time: start time in epoch
            end_time: end time in epoch
            limit: limit of results
            all_result: get all results or not
        Returns:
            logs
        """
        headers = {"kbn-version": "5.1.1-SNAPSHOT", "Content-Type": "application/json"}

        params = {
            "size": 200,
            "sort": [{"indexTime": "asc"}],
            "query": {
                "bool": {
                    "filter": {
                        "bool": {
                            "minimum_should_match": 1,
                            "must_not": [],
                            "should": [],
                        }
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

        if all_result:
            params["size"] = 10000

        return self._http_request(
            "POST",
            full_url=f"{self._base_url}/api/datalake/search",
            headers=headers,
            params=params,
        )


""" COMMAND FUNCTIONS """


# def query_datalake_command(client: Client, args: dict) -> CommandResults:
#     """
#     Args:
#         args: demisto.args()
#     Returns:
#         logs
#     """
#     query = args.get("query", "*")
#     # start_time = args.get("start_time")
#     start_time = 1626118800  # July 12, 2021 00:00:00 UTC in seconds

#     # end_time = args.get("end_time")
#     # limit = int(args.get("limit", 50))
#     # all_result = argToBoolean(args.get("all_result", False))

#     headers = {"kbn-version": "5.1.1-SNAPSHOT", "Content-Type": "application/json"}

#     # params = {
#     #     "size": 200,
#     #     "sort": [{"indexTime": {"order": "asc"}}],
#     #     "query": {
#     #         "bool": {
#     #             "filter": [],
#     #             "must": [
#     #                 query,
#     #                 {
#     #                     "range": {
#     #                         "indexTime": {
#     #                             "gte": start_time * 1000,
#     #                             "format": "epoch_millis"
#     #                         }
#     #                     }
#     #                 }
#     #             ]
#     #         }
#     #     }
#     # }


#     # params2 = json.dumps(params)

#     # response = requests.post(full_url, params=params, headers=headers, timeout=120, verify=False, json=search_query)

#     params = {
#         "size": 200,
#         "sort": [{"indexTime": "asc"}],
#         "query": {
#             "bool": {
#                 "filter": {
#                     "bool": {"minimum_should_match": 1, "must_not": [], "should": []}
#                 },
#                 "must": {
#                     "bool": {
#                         "must_not": [],
#                         "must": [
#                             query,
#                             {
#                                 "range": {
#                                     "indexTime": {
#                                         "gte": start_time * 1000,
#                                         "format": "epoch_millis",
#                                     }
#                                 }
#                             },
#                         ],
#                     }
#                 },
#             }
#         },
#     }
#     params2 = json.dumps(params)

#     response = client._http_request(
#         "POST",
#         full_url=f"{client._base_url}/dl/api/es/search",
#         json_data=params,
#         headers=headers,
#         timeout=120,
#         resp_type="text",
#     )

#     response = response.json()["hits"]["hits"]

#     return CommandResults(outputs_prefix="ExabeamDataLake.Log", outputs=response)


def query_datalake_command(client: Client, args: dict) -> CommandResults:
    """
    Args:
        args: demisto.args()
    Returns:
        logs
    """
    query = args.get("query", "*")
    json.dumps(query)

    # start_time = args.get("start_time")

    # end_time = args.get("end_time")
    # limit = int(args.get("limit", 50))
    # all_result = argToBoolean(args.get("all_result", False))

    headers = {"kbn-version": "5.1.1-SNAPSHOT", "Content-Type": "application/json"}

    params = {
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": query
                        }
                    }
                ]
            }
        }
    }
    params2 = json.dumps(params).encode("utf-8")

    response = client._http_request(
        "POST",
        full_url=f"{client._base_url}/dl/api/es/search",
        data=params2,
        headers=headers,
    )

    response = response.json()["hits"]["hits"]

    return CommandResults(outputs_prefix="ExabeamDataLake.Log", outputs=response)


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
