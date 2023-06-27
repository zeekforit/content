
import requests
import json
import dateutil.parser

# Base URL
baseURL = demisto.params()['url']
VERIFY = not demisto.params().get('insecure', False)
PROXIES = handle_proxy(proxy_param_name='proxy')  # Add this line to handle proxy settings


# Handle proxy settings
def handle_proxy(proxy_param_name):
    proxy = demisto.params().get(proxy_param_name)
    if not proxy:
        return {}
    proxies = {
        "http": proxy,
        "https": proxy
    }
    return proxies

# Obtain access token
def get_access_token():
    url = f"{baseURL}/auth/v1/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": demisto.params()['client_id'],
        "client_secret": demisto.params()['client_secret']
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }
    response = requests.post(url, json=payload, headers=headers, verify=VERIFY, proxies=PROXIES)
    if response.status_code != 200:
        raise Exception(f'Failed to authenticate with Exabeam: {response.status_code}')
    return response.json()["access_token"]

def http_request(method, url_suffix, data=None):
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": f"Bearer {get_access_token()}"
    }
    response = requests.request(method, baseURL + url_suffix, json=data, headers=headers, verify=VERIFY, proxies=PROXIES)
    if response.status_code != 200:
        try:
            message = response.json()['error']['message']
        except (KeyError, ValueError):
            message = response.text
        raise Exception(f'Request to {url_suffix} failed with status code {response.status_code}: {message}')
    return response.json()

# Search for events
def search_events(filter_query, from_time_millis, end_time_millis, limit=10, distinct=False):
    url_suffix = "/search/v2/events"
    payload = {
        "fields": ["*"],
        "limit": limit,
        "distinct": distinct,
        "filter": filter_query,
        "fromTimeMillis": from_time_millis,
        "endTimeMillis": end_time_millis
    }
    return http_request("POST", url_suffix, data=payload)

def search_events_command(args):
    filter_query = args.get("filter")
    from_time_millis = int(args.get("fromTimeMillis"))
    end_time_millis = int(args.get("endTimeMillis"))
    limit = int(args.get("limit", 3))
    distinct = argToBoolean(args.get("distinct", False))
    events = search_events(filter_query, from_time_millis, end_time_millis, limit, distinct)

    if events and "rows" in events:
        headers = list(events["rows"][0].keys()) if events["rows"] else []
        hr = tableToMarkdown("Search Events Results", events["rows"], headers=headers, headerTransform=pascalToSpace)
    else:
        hr = "No events found"

    return_results(CommandResults(readable_output=hr, outputs_prefix="Exabeam.SearchEvents", outputs_key_field="id", outputs=events))

# Fetch incidents
def fetch_incidents(last_run, first_fetch_time):
    last_fetch = last_run.get("last_fetch")
    # if last_fetch is None:
    #    last_fetch = dateutil.parser.parse(first_fetch_time).timestamp() * 1000
    last_fetch = "1682906460910"
    current_fetch = last_fetch
    fetch_now_time = "1682904660910"
    filter_query = demisto.params().get("filter_query_incidents")
    limit = int(demisto.params().get("limit", 10))

    events = search_events(filter_query, fetch_now_time, last_fetch, limit)

    incidents = []
    if events and "rows" in events:
        for event in events["rows"]:
            incident = {
                "name": f'{event["id"]} - Testing',
                #"occurred": event["timeCompletedMillis"],
                "rawJSON": json.dumps(event)
            }
            incidents.append(incident)

            event_time = "1682904660910"
            current_fetch = max(current_fetch, event_time)

    demisto.setLastRun({"last_fetch": current_fetch})
    demisto.incidents(incidents)

# Main function
def main():
    try:
        command = demisto.command()
        demisto.debug(f'Command being called is {command}')

        if command == 'test-module':
            access_token = get_access_token()
            if access_token:
                return_results('ok')
        elif command == 'exabeam-search-events':
            search_events_command(demisto.args())
        elif command == 'fetch-incidents':
            last_run = demisto.getLastRun()
            first_fetch_time = demisto.params().get("first_fetch", "2 hours")
            fetch_incidents(last_run, first_fetch_time)
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err))

if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()

