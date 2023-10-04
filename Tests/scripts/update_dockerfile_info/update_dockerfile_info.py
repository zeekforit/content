#!/usr/bin/env python3


import json
from pathlib import Path
from demisto_sdk.commands.content_graph.interface import ContentGraphInterface
from demisto_sdk.commands.content_graph.common import ContentType
from demisto_sdk.commands.common.docker_helper import get_python_version



def get_docker_images_content():
    with ContentGraphInterface() as graph:
        integrations = graph.search(content_type=ContentType.INTEGRATION)
        scripts = graph.search(content_type=ContentType.SCRIPT)
        return {s.docker_image for s in integrations + scripts}
        

def main():
    path = Path("/Users/mlainer/dev/demisto/dockerfiles-info/docker_images_metadata.json")
    with path.open() as f:
        docker_info = json.load(f)
    docker_images = get_docker_images_content()
    print(docker_images)
    for docker_image in filter(None, docker_images):
        if ":" not in docker_image:
            repo = docker_image
            tag = "latest"
        elif docker_image.count(":") > 1:
            raise ValueError(f"Invalid docker image: {docker_image}")
        else:
            repo, tag = docker_image.split(":")

        python_version = get_python_version(docker_image)
        if python_version:
            repo = repo.removeprefix("demisto/")
            if repo not in docker_info["docker_images"]:
                docker_info["docker_images"][repo] = {}
            if tag not in docker_info["docker_images"][repo]:
                docker_info["docker_images"][repo][tag] = {}
            docker_info["docker_images"][repo][tag]["python_version"] = str(python_version)
    with path.open("w") as f:
        json.dump(docker_info, f)


if __name__ == "__main__":
    main()