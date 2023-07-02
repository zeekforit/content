import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def add_comment(args: Dict[str, Any]) -> CommandResults:
    demisto.debug("adding comment AAAAAAAAA")
    comment_entry = [{
        'Comment': args.get('comment', ''),
        'Comment time': datetime.now().isoformat(),
        'Reviwer': demisto.context().get('username', '')
    }]
    comment_body = str(comment_entry)
    tags = argToList(args.get('tags', ''))

    # Get the incident details
    incident = demisto.incident()
    customFields = incident.get('CustomFields', [])
    demisto.debug(f"\n \n \n CustomFields: {customFields}")
    demisto.debug(f"\n \n \n CustomFields[SplunkComments]: {customFields['SplunkComments']}")
    newcomment = json.loads(customFields['SplunkComments'])
    newcomment += comment_entry
    demisto.debug(f"\n \n \n new comments: {newcomment}")
    customFields['SplunkComments'] = newcomment

    demisto.debug(f"\n \n \n new CustomFields: {customFields}")

    # comments = incident.get('CustomFields', []).get('SplunkComments',[])
    # if isinstance(comments, str):  # Check if comments is a string
    # comments = json.loads(comments)  # Deserialize the string to a list
    # demisto.debug(f"comments {comments}")
    # comments.append(comment_entry)
    # demisto.debug(f"comments {comments}")
    # # # Update the incident labels
    # labels = incident.get('labels', [])
    # labels.append({'type': 'SplunkComments', 'value': str(comment_entry)})
    # demisto.debug(f"new labels {labels}")
    # # Execute the setIncident command to update the incident in the context
    if customFields:
        res = demisto.executeCommand('setIncident', {'customFields': customFields})
    if is_error(res):
        return_error(f'Failed to update incident. Error: {str(res)}')
    # incident = demisto.incident()
    # demisto.debug(f"new incident: {incident}")
    return CommandResults(
        readable_output=comment_body, mark_as_note=True, tags=tags or None
    )


def main():  # pragma: no cover
    try:
        demisto.debug('SplunkAddComment is being called')
        res = add_comment(demisto.args())
        return_results(res)

    except Exception as ex:
        return_error(f'Failed to execute SplunkAddComment. Error: {str(ex)}')


if __name__ in ["__builtin__", "builtins", '__main__']:
    main()
