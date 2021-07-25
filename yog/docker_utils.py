import datetime
import json
import re
import typing as t

import requests
from docker.models.containers import Container
from docker.models.images import Image
from requests import Response

from yog.necronomicon import DockerContainer

DOCKER_DIGEST_HEADER = "Docker-Content-Digest"


class Registry:
    host: str
    proto: str

    def __init__(self, host, proto="http"):
        self.host = host
        self.proto = proto

    def list_repositories(self) -> t.List[str]:
        resp: Response = self._check_call(f"{self.proto}://{self.host}:5000/v2/_catalog")
        repos = resp.json()["repositories"]
        return repos

    def list_tags(self, repo: str) -> t.List[str]:
        resp: Response = self._check_call(f"{self.proto}://{self.host}:5000/v2/{repo}/tags/list")
        return resp.json()["tags"]

    def get_digest(self, repo: str, tag: str) -> str:
        resp: Response = self._check_call(f"{self.proto}://{self.host}:5000/v2/{repo}/manifests/{tag}", requests.get,
                                          headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"})
        digest = resp.headers[DOCKER_DIGEST_HEADER]
        return digest

    def get_create_date(self, repo: str, tag: str) -> datetime.datetime:
        resp: Response = self._check_call(f"{self.proto}://{self.host}:5000/v2/{repo}/manifests/{tag}", requests.get,
                                          headers={"Accept": "application/vnd.docker.distribution.manifest.v1+json"})
        raw_dt = json.loads(resp.json()["history"][0]["v1Compatibility"])["created"]
        return datetime.datetime.strptime(raw_dt[:len("yyyy-mm-ddThh:mm:ss.ffffff")], "%Y-%m-%dT%H:%M:%S.%f")

    def delete_image(self, repo: str, digest: str):
        self._check_call(f"{self.proto}://{self.host}:5000/v2/{repo}/manifests/{digest}", requests.delete)

    def get_contents(self) -> t.Dict[str, t.List['DockerImage']]:
        contents = {}
        for repo in self.list_repositories():
            tags = self.list_tags(repo)
            images = []
            for tag in tags:
                images.append(DockerImage(repo, tag, self.get_digest(repo, tag), self.get_create_date(repo, tag)))
            contents[repo] = images

        return contents

    def _check_call(self, url, fn: t.Callable = requests.get, headers=None):
        resp: Response = fn(url, headers=headers)
        if not resp.ok:
            raise ValueError(f"Request to {url} had code: {resp.status_code}: {resp.text}")
        return resp


class DockerImage(t.NamedTuple):
    repo: str
    tag: str
    digest: str
    created: datetime.datetime


def my_format_to_run_ports_arg_format(port_section: t.Mapping[str, str]):
    def format_host_expr(host_expr: str) -> t.Tuple[str, str]:
        md: re.Match = re.fullmatch(r"((?P<addr>\d+\.\d+\.\d+\.\d+):)?(?P<port>\d+)(/(?P<proto>tcp|udp))?",
                                host_expr)  # 0.0.0.0:53/tcp

        return md.group("addr") if md.group("addr") else '0.0.0.0', md.group("port")

    def format_container_port_expr(container_port_expr: str) -> str:
        return container_port_expr if container_port_expr.endswith("/tcp") or container_port_expr.endswith(
            "/udp") else f"{container_port_expr}/tcp"

    ret = dict()
    for k, v in port_section.items():
        new_key = format_container_port_expr(v)
        new_value = format_host_expr(k)

        if new_key in ret:
            ret[new_key].append(new_value)
        else:
            ret[new_key] = [new_value]

    #print(ret)
    return ret


def my_format_to_ports_attr_format(port_section: t.Mapping[str, str]):
    """Converts my YAML format, which is the same as the docker CLI -p format, to what the docker API expects
    MY format is:
        key: <host addr>:<host port>/<proto>
        value: <dest container port>/<proto>
    What the API expects is:
    A dict where the keys are a str of format: "container port/proto"
           and the values are a list whose elements are
                              a dict that looks like {HostIp: <HostAddr>, HostPort: <HostPort>}
    Example:
        {
            '33200/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '33200'}],
            '53/tcp': [{'HostIp': '192.168.1.103', 'HostPort': '53'}],
            '53/udp': [{'HostIp': '192.168.1.103', 'HostPort': '53'}]
        }
    """

    def format_host_expr(host_expr: str) -> t.List[t.Dict[str, str]]:
        md: re.Match = re.fullmatch(r"((?P<addr>\d+\.\d+\.\d+\.\d+):)?(?P<port>\d+)(/(?P<proto>tcp|udp))?",
                                host_expr)  # 0.0.0.0:53/tcp

        return [{'HostIp': md.group("addr") if md.group("addr") else '0.0.0.0',
                 'HostPort': md.group('port')}]

    def format_container_port_expr(container_port_expr: str) -> str:
        return container_port_expr if container_port_expr.endswith("/tcp") or container_port_expr.endswith(
            "/udp") else f"{container_port_expr}/tcp"

    #ret = {format_container_port_expr(v): format_host_expr(k) for k, v in port_section.items()}
    ret = dict()
    for k, v in port_section.items():
        key = format_container_port_expr(v)
        value = format_host_expr(k)

        if key not in ret:
            ret[key] = []

        ret[key].extend(value)
        ret[key] = sorted(ret[key], key=lambda entry: (entry["HostIp"], entry["HostPort"]))

    #print(ret)
    return ret


def _ports_match(desired: t.Mapping[int, t.Union[int, str]], ports: t.Mapping[str, t.Mapping[str, str]]):
    expected = my_format_to_ports_attr_format(desired)
    sorted_ports = dict()
    # TODO this breaks if the container EXPOSEs a port but I don't bind it
    for k, v in ports.items():
        if v:
            sorted_ports[k] = sorted(v, key=lambda entry: (entry["HostIp"], entry["HostPort"]))
    return expected == sorted_ports


def _envs_match(desired: DockerContainer, found: Container, desired_env):
    found_env_list: t.List[str] = found.attrs['Config']['Env']
    found_env = {l[0]: l[1] for l in (l.split("=", 1) for l in found_env_list) if l[0] in desired.env}
    return found_env == desired_env


def _volumes_match(desired: DockerContainer, found: Container):
    found_mounts_list: t.List[t.Dict[str, t.Any]] = found.attrs['Mounts']
    found_mounts_volume = {m['Name']: m['Destination'] for m in found_mounts_list if m['Type'] == 'volume'}
    found_mounts_bind = {m['Source']: m['Destination'] for m in found_mounts_list if m['Type'] == 'bind'}
    found_mounts = {}
    for k, v in found_mounts_volume.items():
        if k in desired.volumes:
            found_mounts[k] = v

    for k, v in found_mounts_bind.items():
        if k in desired.volumes:
            found_mounts[k] = v

    return found_mounts == desired.volumes


def _commands_match(desired: DockerContainer, found: Container):
    if desired.command:
        return desired.command.split(" ") == found.attrs["Config"]["Cmd"]
    else:
        return found.image.attrs['Config']['Cmd'] == found.attrs["Config"]["Cmd"]


def is_acceptable_container(c: Container, img_by_digest: Image, desired: DockerContainer, desired_env):
    return c.image.id == img_by_digest.id and \
           c.status in ["running"] and \
           _ports_match(desired.ports, c.ports) and \
           _envs_match(desired, c, desired_env) and \
           _volumes_match(desired, c) and \
           _commands_match(desired, c)


