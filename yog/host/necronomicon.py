import logging
import typing as t
from dataclasses import dataclass
from ipaddress import ip_address, IPv4Address

import yaml
from paramiko.client import SSHClient

from yog.ssh_utils import check_stdout


def loads(ident: str, necronomicon: str) -> 'Necronomicon':
    return load(ident, yaml.safe_load(necronomicon))


def loadfile(ident: str, path: str) -> 'Necronomicon':
    with open(path) as nin:
        return loads(ident, nin.read())


def load(ident: str, parsed_necronomicon) -> 'Necronomicon':
    if parsed_necronomicon is None:
        return Necronomicon(ident, NeededTunnelsSection([]), DockerSection([]), CronSection([]), FileSection([]))

    if 'files' in parsed_necronomicon:
        fs = FileSection([File(
            e['src'],
            e['dest'],
            e['hupcmd'] if 'hupcmd' in e else None,
            e['root'] if 'root' in e else False,
        ) for e in parsed_necronomicon['files']])
    else:
        fs = FileSection([])

    if 'docker' in parsed_necronomicon:
        ds = DockerSection([DockerContainer(
            e['image'],
            e['name'],
            e['fingerprint'],
            e['volumes'] if 'volumes' in e else {},
            [PortEntry.from_yaml(pe) for pe in (e['ports'] if 'ports' in e else [])],
            e['env'] if 'env' in e else {},
            e['command'] if 'command' in e else None,
            e['capabilities'] if 'capabilities' in e else [],
            {str(k): str(v) for k, v in e['sysctls'].items()} if 'sysctls' in e else {},
        ) for e in parsed_necronomicon['docker']])
    else:
        ds = DockerSection([])

    if 'cron' in parsed_necronomicon:
        cs = CronSection([CronJob(e['expr'], e['command'], e['user'] if 'user' in e else 'root') for e in parsed_necronomicon['cron']])
    else:
        cs = CronSection([])

    if 'needs_tunnels' in parsed_necronomicon:
        tunnels = NeededTunnelsSection([
            NeededTunnel(
                tun['host'],
                int(tun['target_port']),
                int(tun['local_port']),
            ) for tun in parsed_necronomicon['needs_tunnels']
        ])
    else:
        tunnels = NeededTunnelsSection([])

    return Necronomicon(ident, tunnels, ds, cs, fs)


class Necronomicon(t.NamedTuple):
    ident: str
    tunnels: 'NeededTunnelsSection'
    docker: 'DockerSection'
    cron: 'CronSection'
    files: 'FileSection'

    def inflate(self, host: str, ssh: SSHClient) -> 'Necronomicon':
        inflated_containers = []
        for desired_container in self.docker.containers:
            inflated_desired_container_env = {}
            for name, value in desired_container.env.items():
                value = str(value)
                if value.startswith("yogreadfile:"):
                    try:
                        inflated_desired_container_env[name] = "\n".join(
                            check_stdout(ssh, f"sudo cat {value[len('yogreadfile:'):]}")).strip()
                    except RuntimeError as err:
                        logging.error(f"Error processing yogreadfile: {value}", exc_info=err)
                        raise RuntimeError(f"Error accessing file: {value[len('yogreadfile:'):]}")
                else:
                    inflated_desired_container_env[name] = value
            inflated_containers.append(DockerContainer(
                desired_container.image,
                desired_container.name,
                desired_container.fingerprint,
                desired_container.volumes,
                desired_container.ports,
                inflated_desired_container_env,
                desired_container.command,
                desired_container.capabilities,
                desired_container.sysctls,
            ))

        return Necronomicon(
            self.ident,
            self.tunnels,
            DockerSection(inflated_containers),
            self.cron,
            self.files,
        )


class DockerSection(t.NamedTuple):
    containers: t.List['DockerContainer']


class DockerContainer(t.NamedTuple):
    image: str
    name: str
    fingerprint: str
    volumes: t.Mapping[str, str]
    ports: t.List['PortEntry']
    env: t.Mapping[str, str]
    command: t.Optional[str]
    capabilities: t.List[str]
    sysctls: t.Mapping[str, str]


class PortEntry(t.NamedTuple):
    container: 'PortString'
    host: t.List['PortString']

    @staticmethod
    def from_yaml(y) -> 'PortEntry':
        return PortEntry(
            PortString.from_str(y["container"], allow_ip=False),
            sorted([PortString.from_str(s, allow_proto=False) for s in y["host"]]),
        )

    def __str__(self):
        host_part = ",".join([str(ps) for ps in self.host])
        return f"{self.container}->{host_part}"

    def __repr__(self) -> str:
        return str(self)

    def __lt__(self, other):
        return str(self) < str(other)


@dataclass
class PortString:
    ip: t.Union[IPv4Address, None]
    port: int
    proto: t.Union[str, None]

    def as_run_arg_key(self) -> t.Union[str, int]:
        if self.proto:
            return f"{self.port}/{self.proto}"
        else:
            return self.port

    def as_run_arg_value(self) -> t.Union[int, t.Tuple[str, int]]:
        if self.ip:
            return str(self.ip), self.port
        else:
            return self.port

    def __str__(self) -> str:
        return f"{str(self.ip) if self.ip else '0.0.0.0'}:{self.port}/{self.proto if self.proto else 'any'}"

    def __eq__(self, o: object) -> bool:
        return str(self) == str(o)

    def __lt__(self, other):
        return str(self) < str(other)

    @staticmethod
    def _normalize(ip: t.Union[IPv4Address, None], port: int, proto: t.Union[str, None], allow_proto=True, allow_ip=True):
        if not allow_ip and ip:
            raise ValueError(f"IP is not allowed (is meaningless) for port expr {ip},{port},{proto}")
        if not allow_proto and proto:
            raise ValueError(F"Protocol is not allowed (is meaningless) for port expr {ip},{port},{proto}")

        if allow_proto and not proto:
            proto = 'tcp'
        if allow_ip and not ip:
            ip = ip_address('0.0.0.0')

        return ip, port, proto

    @staticmethod
    def from_tuple(ip: t.Union[IPv4Address, None], port: int, proto: t.Union[str, None], allow_proto=True, allow_ip=True):
        ip, port, proto = PortString._normalize(ip, port, proto, allow_proto, allow_ip)
        return PortString(ip, port, proto)

    @staticmethod
    def from_str(s: str, allow_proto=True, allow_ip=True) -> 'PortString':
        if isinstance(s, int):
            s = str(s)

        if "/" in s:
            ipport, proto = s.split("/")
        else:
            ipport = s
            proto = None

        if ":" in ipport:
            ip, port = ipport.split(":")
            port = int(port)
        else:
            port = int(ipport)
            ip = None

        ip, port, proto = PortString._normalize(ip, port, proto, allow_proto, allow_ip)
        return PortString(ip_address(ip) if ip else None, port, proto)


class CronSection(t.NamedTuple):
    crons: t.List['CronJob']


class CronJob(t.NamedTuple):
    expr: str
    command: str
    user: str


class FileSection(t.NamedTuple):
    files: t.List['File']


class File(t.NamedTuple):
    src: str
    dest: str
    hupcmd: str
    root: bool


class NeededTunnel(t.NamedTuple):
    host: str
    target_port: int
    local_port: int


class NeededTunnelsSection(t.NamedTuple):
    tunnels: t.List[NeededTunnel]