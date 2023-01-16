import ipaddress
import re
import typing as t
from dataclasses import dataclass
from typing import Any

from docker.models.containers import Container
from docker.models.images import Image
from docker.types import LogConfig

from yog.host.necronomicon import DockerContainer, PortEntry, PortString


class DockerAttribute:

    def run_arg_name(self) -> str:
        raise NotImplemented()

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        raise NotImplemented()

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        raise NotImplemented()


class DockerAttributeInstance:
    def to_run_arg(self) -> t.Any:
        raise NotImplemented()

    def is_satisfied_by(self, actual: 'DockerAttributeInstance'):
        raise NotImplemented()


def build_run_kwargs_dict(dc: DockerContainer) -> t.Dict[Any, Any]:
    return {a.run_arg_name(): a.from_necronomicon(dc).to_run_arg() for a in SUPPORTED_DOCKER_ATTRS}


class SimpleDockerAttributeInstance(DockerAttributeInstance):
    def __init__(self, o):
        self.o = o

    def to_run_arg(self) -> t.Any:
        return self.o

    def is_satisfied_by(self, other: 'SimpleDockerAttributeInstance'):
        return self.o == other.o

    def __repr__(self) -> str:
        return repr(self.o)


ImageName: t.TypeAlias = str
ImageDigest: t.TypeAlias = str


@dataclass
class DockerImageDefInstance(DockerAttributeInstance):
    repo_digests: t.List[t.Tuple[ImageName, ImageDigest]]

    def to_run_arg(self) -> t.Any:
        name, digest = self.repo_digests[0]
        return f"{name}@{digest}"

    def is_satisfied_by(self, other: 'DockerImageDefInstance'):
        return any(rd in other.repo_digests for rd in self.repo_digests)


class DockerImageDef(DockerAttribute):
    def run_arg_name(self) -> str:
        return "image"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return DockerImageDefInstance([(dc.image, dc.fingerprint)])

    def from_container(self, c: Container) -> t.Any:
        rds = c.image.attrs['RepoDigests']
        return DockerImageDefInstance([tuple(rd.split("@")) for rd in rds])


@dataclass
class DockerEnvDefInstance(DockerAttributeInstance):
    env: t.Mapping[str, str]

    def to_run_arg(self) -> t.Any:
        return self.env

    def is_satisfied_by(self, o: 'DockerEnvDefInstance'):
        desired = self
        actual = o
        return all((k in actual.env and actual.env[k] == str(v)) for k, v in desired.env.items())


class DockerEnvDef(DockerAttribute):

    def run_arg_name(self) -> str:
        return "environment"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return DockerEnvDefInstance(dc.env)

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        found_env_list: t.List[str] = c.attrs['Config']['Env']
        found_env = {l[0]: l[1] for l in (l.split("=", 1) for l in found_env_list)}
        return DockerEnvDefInstance(found_env)


class DockerContainerNameDef(DockerAttribute):

    def run_arg_name(self) -> str:
        return "name"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance(dc.name)

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance(c.name)


@dataclass
class DockerPortsDefInstance(DockerAttributeInstance):
    ports: t.List[PortEntry]

    def to_run_arg(self) -> t.Dict[t.Union[str, int], t.Union[int, t.Tuple[str, int]]]:
        return {pe.container.as_run_arg_key(): [hv.as_run_arg_value() for hv in pe.host] for pe in self.ports}

    def is_satisfied_by(self, actual: 'DockerPortsDefInstance'):
        return sorted(self.ports) == sorted(actual.ports)


class DockerPortsDef(DockerAttribute):
    def run_arg_name(self) -> str:
        return "ports"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return DockerPortsDefInstance(dc.ports)

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        """
        Example: {
            '33200/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '33200'}],
            '53/tcp': [{'HostIp': '192.168.1.103', 'HostPort': '53'}],
            '53/udp': [{'HostIp': '192.168.1.103', 'HostPort': '53'}]
        }
        """

        ret = []
        for container_port, host_ports in c.ports.items():
            ret.append(PortEntry(
                PortString.from_str(container_port, allow_ip=False),
                sorted([PortString.from_tuple(ipaddress.ip_address(hp['HostIp']) if hp['HostIp'] != '0.0.0.0' else None, int(hp['HostPort']), None, allow_proto=False) for hp in host_ports if ipaddress.ip_address(hp['HostIp']).version == 4]) if host_ports else [],
            ))

        return DockerPortsDefInstance(ret)


@dataclass
class DockerVolumesDefInstance(DockerAttributeInstance):
    volumes: t.Mapping[str, str]

    def to_run_arg(self) -> t.Any:
        ret = {}
        for k, v in self.volumes.items():
            mode_data = re.search(r"\+(?P<mode>r[ow])$", v)
            if mode_data:
                tmp = {"bind": v[:-3], "mode": mode_data.group("mode").strip()}
                if tmp["bind"].endswith("/"):
                    tmp["bind"] = tmp["bind"][:-1]
                ret[k] = tmp
            else:
                ret[k] = {"bind": v[:-1] if v.endswith("/") else v, "mode": "rw"}

        return ret

    def is_satisfied_by(self, other: 'DockerVolumesDefInstance'):
        return self.volumes == other.volumes


class DockerVolumesDef(DockerAttribute):

    def run_arg_name(self) -> str:
        return "volumes"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerVolumesDefInstance':
        ret = {}
        for k, v in dc.volumes.items():
            if not re.search(r"\+(?P<mode>r[ow])$", v):
                v = f"{v}+rw"
            if v[-4] == "/":
                v = v[:-4] + v[-3:]
            ret[k] = v
        return DockerVolumesDefInstance(ret)

    def from_container(self, c: Container) -> 'DockerVolumesDefInstance':
        found_mounts_list: t.List[t.Dict[str, t.Any]] = c.attrs['Mounts']
        found_mounts_volume = {m['Name']: {"bind": m['Destination'], "mode": m["Mode"]} for m in found_mounts_list if
                               m['Type'] == 'volume'}
        found_mounts_bind = {m['Source']: {"bind": m['Destination'], "mode": m["Mode"]} for m in found_mounts_list if
                             m['Type'] == 'bind'}
        found_mounts = {}
        for k, v in found_mounts_volume.items():
            found_mounts[k] = f"{v['bind']}+{v['mode']}"

        for k, v in found_mounts_bind.items():
            found_mounts[k] = f"{v['bind']}+{v['mode']}"

        return DockerVolumesDefInstance(found_mounts)


@dataclass
class DockerCommandDefInstance(DockerAttributeInstance):
    command: t.Union[t.List[str], None]
    image: t.Union[Image, None]

    def to_run_arg(self) -> t.Any:
        return self.command

    def is_satisfied_by(self, actual: 'DockerCommandDefInstance'):
        if self.command:
            return self.command == actual.command
        else:
            return actual.image.attrs['Config']['Cmd'] == actual.command


class DockerCommandDef(DockerAttribute):
    def run_arg_name(self) -> str:
        return "command"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return DockerCommandDefInstance(dc.command.split(" ") if dc.command else None, None)

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        return DockerCommandDefInstance(c.attrs["Config"]["Cmd"], c.image)


class DockerSysctlDef(DockerAttribute):
    sysctls: t.Mapping[str, str]

    def run_arg_name(self) -> str:
        return "sysctls"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance(dc.sysctls)

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        if 'Sysctls' in c.attrs['HostConfig']:
            return SimpleDockerAttributeInstance(c.attrs['HostConfig']['Sysctls'])
        else:
            return SimpleDockerAttributeInstance({})


class DockerCapabilitiesDef(DockerAttribute):

    def run_arg_name(self) -> str:
        return "cap_add"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance(dc.capabilities)

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        theirs = c.attrs['HostConfig']['CapAdd']
        if theirs is None:
            theirs = []
        return SimpleDockerAttributeInstance(theirs)


class DockerDetachDef(DockerAttribute):
    def run_arg_name(self) -> str:
        return "detach"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance(True)

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance(True)


class DockerLoggingDef(DockerAttribute):
    def run_arg_name(self) -> str:
        return "log_config"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance(LogConfig(type=LogConfig.types.JOURNALD))

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance(c.attrs['HostConfig']['LogConfig'])


class DockerRestartPolicyDef(DockerAttribute):
    def run_arg_name(self) -> str:
        return "restart_policy"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance({'Name': "always"})

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        found = c.attrs['HostConfig']['RestartPolicy']
        return SimpleDockerAttributeInstance({'Name': found['Name']})


class DockerNameDef(DockerAttribute):
    def run_arg_name(self) -> str:
        return "name"

    def from_necronomicon(self, dc: DockerContainer) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance(dc.name)

    def from_container(self, c: Container) -> 'DockerAttributeInstance':
        return SimpleDockerAttributeInstance(c.name)


def diff_container(c: Container, dc: DockerContainer) -> t.List[t.Tuple[str, t.Any, t.Any]]:
    diffs = []
    for da in SUPPORTED_DOCKER_ATTRS:
        desired = da.from_necronomicon(dc)
        found = da.from_container(c)

        if not desired.is_satisfied_by(found):
            diffs.append((da.run_arg_name(), desired, found))
    return diffs


SUPPORTED_DOCKER_ATTRS: t.List['DockerAttribute'] = [
    DockerImageDef(),
    DockerEnvDef(),
    DockerContainerNameDef(),
    DockerPortsDef(),
    DockerVolumesDef(),
    DockerCommandDef(),
    DockerSysctlDef(),
    DockerCapabilitiesDef(),
    DockerDetachDef(),
    DockerLoggingDef(),
    DockerRestartPolicyDef(),
    DockerNameDef(),
]
