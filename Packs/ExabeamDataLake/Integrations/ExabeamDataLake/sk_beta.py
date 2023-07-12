import requests
import demistomock as demisto
from CommonServerPython import *  # noqa
from CommonServerUserPython import *  # noqa

# disable insecure warnings
requests.packages.urllib3.disable_warnings()

TOKEN_INPUT_IDENTIFIER = "__token"


class Client(BaseClient):
    """
    Client to use in the Exabeam integration. Overrides BaseClient
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool,
        proxy: bool,
        headers,
    ):
        super().__init__(
            base_url=f"{base_url}", headers=headers, verify=verify, proxy=proxy
        )
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers = headers
        if not proxy:
            self.session.trust_env = False
        if self.username != TOKEN_INPUT_IDENTIFIER:
            self._login()

    def __del__(self):
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
        self._http_request(
            "GET", full_url=f"{self._base_url}/api/auth/check", resp_type="text"
        )


""" COMMANDS """


def test_module(client: Client, *_):
    """test function

    Args:
        client: Client

    Returns:
        ok if successful
    """
    client.test_module_request()
    demisto.results("ok")
    return "", None, None


def query_datalake(self, start_time: int = None, query: str = None):
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


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    username = demisto.params().get("credentials").get("identifier")
    password = demisto.params().get("credentials").get("password")
    base_url = demisto.params().get("url")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)
    headers = {"Accept": "application/json", "Csrf-Token": "nocheck"}
    if username == TOKEN_INPUT_IDENTIFIER:
        headers["ExaAuthToken"] = password

    try:
        client = Client(
            base_url.rstrip("/"),
            verify=verify_certificate,
            username=username,
            password=password,
            proxy=proxy,
            headers=headers,
        )
        command = demisto.command()
        LOG(f"Command being called is {command}.")
        if command == "test-module":
            test_module(client)
        else:
            query_datalake(client)  # type: ignore
        # else:
        # raise NotImplementedError(f'Command "{command}" is not implemented.')

    except DemistoException as err:
        # some of the API error responses are not so clear, and the reason for the error is because of bad input.
        # we concat here a message to the output to make sure
        error_msg = str(err)
        if err.res is not None and err.res.status_code == 500:
            error_msg += (
                "\nThe error might have occurred because of incorrect inputs. "
                "Please make sure your arguments are set correctly."
            )
        return_error(error_msg)

    except Exception as err:
        return_error(str(err))


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
