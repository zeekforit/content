from genericpath import isfile
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import tarfile
import io
import json

from demisto_sdk.commands.common.constants import ENTITY_TYPE_TO_DIR, METADATA_FILE_NAME, PACKS_DIR
from demisto_sdk.commands.content_graph.common import ContentType, RelationshipType
from demisto_sdk.commands.content_graph.parsers.content_item import ContentItemParser
from demisto_sdk.commands.content_graph.parsers.integration import CommandParser
from pathlib import Path
from tempfile import TemporaryDirectory


BUNDLE_FILNAME = "bundle.tar.gz"
CUSTOM_CONTENT_PACK_NAME = "CustomContent"

CONTENT_ITEMS_TO_IGNORE = ["automation-CommonUserServer", "automation-CommonServerUser"]


def should_skip(file_name: str):
    return any(f in file_name for f in CONTENT_ITEMS_TO_IGNORE)


def init_pack(root_dir: Path) -> Path:
    pack_path = root_dir / PACKS_DIR / CUSTOM_CONTENT_PACK_NAME
    pack_path.mkdir(parents=True, exist_ok=True)
    metadata_path = pack_path / METADATA_FILE_NAME
    metadata_path.write_text(
        json.dumps(
            {
                "name": CUSTOM_CONTENT_PACK_NAME,
                "description": "",
                "support": "xsoar",
                "currentVersion": "1.0.0",
                "author": "Cortex XSOAR",
                "url": "https://www.paloaltonetworks.com/cortex",
                "email": "",
                "created": "2020-03-10T08:37:18Z",
                "certification": "verified",
                "categories": [],
                "tags": [],
                "useCases": [],
                "keywords": [],
                "dependencies": {},
                "marketplaces": [],
            },
        )
    )
    return pack_path


def download_bundle() -> None:
    # this shouldn't be here, instead use the script directly.
    # I should transform the script to integration and use the context.

    # demisto.debug("Downloading the custom content tar.gz file")
    # execute_command(
    #     "demisto-api-download",
    #     {"uri": "/content/bundle", "filename": BUNDLE_FILNAME},
    #     fail_on_error=True,
    # )
    # demisto.debug("Downloaded the custom content tar.gz file")
    entry_id = demisto.dt(demisto.context(), f"File(val.Name == '{BUNDLE_FILNAME}').EntryID")
    if not entry_id:
        raise Exception(
            f"No file entry with name {BUNDLE_FILNAME} found, "
            "please run: `!demisto-api-download uri=\"/content/bundle\" filename=bundle.tar.gz`"
        )
    entry_id = entry_id[-1] if isinstance(entry_id, list) else entry_id
    demisto.debug(f"{entry_id=}")
    file = demisto.getFilePath(entry_id)
    with open(file["path"], "rb") as f:
        return f.read()


def build_custom_content_pack(root_dir: Path) -> Path:
    # pack_path = init_pack(root_dir)
    pack_path = root_dir / PACKS_DIR / CUSTOM_CONTENT_PACK_NAME
    bundle_bytes_data = download_bundle()
    with tarfile.open(fileobj=io.BytesIO(bundle_bytes_data), mode="r:gz") as tar:
        for file in tar.getmembers():
            filename = file.name.lstrip("/")
            if should_skip(filename):
                continue
            entity_type = filename.split("-")[0]
            path_to_extract = pack_path / ENTITY_TYPE_TO_DIR[entity_type]
            demisto.debug(f"Extracting {filename}")
            path_to_extract.mkdir(parents=True, exist_ok=True)
            (path_to_extract / filename).write_bytes(tar.extractfile(file).read())

    return pack_path


def get_relationships(
        source: ContentItemParser,
        content_item_id: str,
        content_item_name: str,
        content_type: ContentType,
    ) -> list:
    results = []
    for rel_type in [
        RelationshipType.USES_BY_ID,
        RelationshipType.USES_BY_NAME,
        RelationshipType.USES_COMMAND_OR_SCRIPT,
        RelationshipType.USES_PLAYBOOK,
    ]:
        relationships = source.relationships.get(rel_type) or []
        demisto.debug(f"Iterating {len(relationships)} {rel_type} relationships")
        for relationship_data in relationships:
            if relationship_data["target"] in [content_item_id, content_item_name] \
                and (content_type in ContentType(relationship_data["target_type"]).labels \
                    or (content_type in [ContentType.COMMAND, ContentType.SCRIPT] \
                        and relationship_data["target_type"] == ContentType.COMMAND_OR_SCRIPT)):
                demisto.debug(f"Found relationship: {json.dumps(relationship_data, indent=4)}")
                results.append({
                    "ContentItemID": source.object_id,
                    "ContentItemName": source.name,
                    "ContentType": source.content_type,
                })
    return results


def get_content_item_name(pack_path: Path, content_item_id: str, content_type: ContentType) -> str:
    if content_type == ContentType.COMMAND:
        return content_item_id
    for path in (pack_path / content_type.as_folder).rglob("*"):
        if path.is_file():
            c = ContentItemParser.from_path(path)
            if content_item_id == c.object_id:
                return c.name
            elif content_item_id == c.name:
                return c.object_id
    raise ValueError(f"Content item {content_item_id} of type {content_type} not found")


def main():
    result = []
    args = demisto.args()
    content_item_id = args["content_item"]
    content_type = ContentType(args["content_type"])
    with TemporaryDirectory() as root_dir:
        pack_path = build_custom_content_pack(Path(root_dir))
        content_item_name = get_content_item_name(pack_path, content_item_id, content_type)
        for path in pack_path.rglob("*"):
            if path.is_file():
                c = ContentItemParser.from_path(path)
                result.extend(get_relationships(c, content_item_id, content_item_name, content_type))


        return_results(
            CommandResults(
                outputs={"ContentItem": content_item_id, "ContentType": content_type, "Usages": result},
                outputs_prefix="CustomContentUsages",
                outputs_key_field=["ContentItem", "ContentType"],
                readable_output=tableToMarkdown(
                    f"{content_item_id} {content_type} - Using Content Items",
                    result,
                    headers=["ContentItemID", "ContentItemName", "ContentType"],
                    headerTransform=pascalToSpace,
                ),
            )
        )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
