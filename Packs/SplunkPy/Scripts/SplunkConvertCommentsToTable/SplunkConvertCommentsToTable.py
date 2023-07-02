import demistomock as demisto
from CommonServerPython import *


def main():
    incident = demisto.incident()
    splunkComments = []
    demisto.debug(f"incidens: {incident}")
    if not incident:
        raise ValueError("Error - demisto.incident() expected to return current incident "
                         "from context but returned None")
    fields = incident.get('CustomFields', [])
    if fields:
        splunkComments = json.loads(fields.get('SplunkComments', []))
        demisto.debug(f"{fields} \n\n\n SplunkComments: {splunkComments} \n\n\n {type(splunkComments)}")
    # labels = incident.get('labels', [])
    # demisto.debug(labels)
    # incident_comments = []
    # for label in labels:
    #     if label.get('type') == 'SplunkComments':
    #         incident_comments = json.loads(label.get('value', []))
    #         demisto.debug(incident_comments)
    if not splunkComments:
        return CommandResults(readable_output='No comments were found in the notable')

    # incident_comments.append(splunkComments)
    # demisto.debug(f"incident_comments: {incident_comments}")
    markdown = tableToMarkdown("", splunkComments, headers=['Comment', 'Comment time', 'Reviwer'])
    demisto.debug(f"markdown {markdown}")

    return {'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': markdown}


if __name__ in ('__main__', '__builtin__', 'builtins'):
    try:
        return_results(main())
    except Exception as e:
        return_error(f'Got an error while parsing Splunk events: {e}', error=e)
