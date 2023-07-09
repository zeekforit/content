import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def add_comment(args: Dict[str, Any]) -> CommandResults:
    demisto.debug("adding comment AAAAAAAAA")
    tags = argToList(args.get('tags', 'FROM XSOAR'))

    comment_entry = {
        'Comment': args.get('comment', ''),
        'Comment time': datetime.now().isoformat(),
        'Reviwer': demisto.context().get('username', ''),
        'Tag': tags
    }

    comment_body = comment_entry.get('Comment')

    # Get the incident details
    incident = demisto.incident()
    customFields = incident.get('CustomFields', [])
    newcomment = customFields.get('SplunkComments', [])
    newcomment += [comment_entry]
    customFields['SplunkComments'] = newcomment

    demisto.debug(f"\n \n \n new CustomFields: {customFields}")

    #  Execute the setIncident command to update the incident in the context
    if customFields:
        res = demisto.executeCommand('setIncident', {'customFields': customFields})
        if is_error(res):
            return_error(f'Failed to update incident. Error: {str(res)}')

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
