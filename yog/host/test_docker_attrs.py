import logging
import unittest
from unittest.mock import MagicMock

import yaml
from docker.models.containers import Container
from docker.models.images import Image

from yog.host.docker_attrs import SUPPORTED_DOCKER_ATTRS
from yog.host.necronomicon import DockerContainer, load
from yog.res import get_resource


class TestDockerAttrs(unittest.TestCase):

    def test_docker_container_equals(self):
        n = load("dockertest", yaml.safe_load(get_resource("docker_test.yml")))

        c: MagicMock = MagicMock(spec=Container)

        c.attrs = {'Id': '73d4999164755197142a155133c022baec3817ad91071741927bcc2f384c7f0c', 'Created': '2023-01-30T03:40:36.570012116Z', 'Path': 'docker-entrypoint.sh', 'Args': ['/usr/bin/dumb-init', 'node', 'server.js'], 'State': {'Status': 'running', 'Running': True, 'Paused': False, 'Restarting': False, 'OOMKilled': False, 'Dead': False, 'Pid': 1282, 'ExitCode': 0, 'Error': '', 'StartedAt': '2023-01-30T05:12:09.960486407Z', 'FinishedAt': '2023-01-30T04:38:46.01411325Z'}, 'Image': 'sha256:c90b263d8a383ac55905e4edbe1513ba87b1a479bcaa8bb471412137b9541751', 'ResolvConfPath': '/var/lib/docker/containers/73d4999164755197142a155133c022baec3817ad91071741927bcc2f384c7f0c/resolv.conf', 'HostnamePath': '/var/lib/docker/containers/73d4999164755197142a155133c022baec3817ad91071741927bcc2f384c7f0c/hostname', 'HostsPath': '/var/lib/docker/containers/73d4999164755197142a155133c022baec3817ad91071741927bcc2f384c7f0c/hosts', 'LogPath': '', 'Name': '/wg-in-test', 'RestartCount': 0, 'Driver': 'overlay2', 'Platform': 'linux', 'MountLabel': '', 'ProcessLabel': '', 'AppArmorProfile': 'docker-default', 'ExecIDs': None, 'HostConfig': {'Binds': ['/srv/wg-in/config:/etc/wireguard:rw'], 'ContainerIDFile': '', 'LogConfig': {'Type': 'journald', 'Config': {}}, 'NetworkMode': 'default', 'PortBindings': {'51820/udp': [{'HostIp': '0.0.0.0', 'HostPort': '51820'}], '51821/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '51821'}]}, 'RestartPolicy': {'Name': 'always', 'MaximumRetryCount': 0}, 'AutoRemove': False, 'VolumeDriver': '', 'VolumesFrom': None, 'CapAdd': ['NET_ADMIN', 'SYS_MODULE'], 'CapDrop': None, 'CgroupnsMode': 'host', 'Dns': [], 'DnsOptions': [], 'DnsSearch': [], 'ExtraHosts': None, 'GroupAdd': None, 'IpcMode': 'private', 'Cgroup': '', 'Links': None, 'OomScoreAdj': 0, 'PidMode': '', 'Privileged': False, 'PublishAllPorts': False, 'ReadonlyRootfs': False, 'SecurityOpt': None, 'UTSMode': '', 'UsernsMode': '', 'ShmSize': 67108864, 'Sysctls': {'net.ipv4.conf.all.forwarding': '1', 'net.ipv4.conf.all.proxy_arp': '1', 'net.ipv4.conf.all.src_valid_mark': '1', 'net.ipv4.ip_forward': '1'}, 'Runtime': 'runc', 'ConsoleSize': [0, 0], 'Isolation': '', 'CpuShares': 0, 'Memory': 0, 'NanoCpus': 0, 'CgroupParent': '', 'BlkioWeight': 0, 'BlkioWeightDevice': None, 'BlkioDeviceReadBps': None, 'BlkioDeviceWriteBps': None, 'BlkioDeviceReadIOps': None, 'BlkioDeviceWriteIOps': None, 'CpuPeriod': 0, 'CpuQuota': 0, 'CpuRealtimePeriod': 0, 'CpuRealtimeRuntime': 0, 'CpusetCpus': '', 'CpusetMems': '', 'Devices': None, 'DeviceCgroupRules': None, 'DeviceRequests': None, 'KernelMemory': 0, 'KernelMemoryTCP': 0, 'MemoryReservation': 0, 'MemorySwap': 0, 'MemorySwappiness': None, 'OomKillDisable': False, 'PidsLimit': None, 'Ulimits': None, 'CpuCount': 0, 'CpuPercent': 0, 'IOMaximumIOps': 0, 'IOMaximumBandwidth': 0, 'MaskedPaths': ['/proc/asound', '/proc/acpi', '/proc/kcore', '/proc/keys', '/proc/latency_stats', '/proc/timer_list', '/proc/timer_stats', '/proc/sched_debug', '/proc/scsi', '/sys/firmware'], 'ReadonlyPaths': ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger']}, 'GraphDriver': {'Data': {'LowerDir': '/var/lib/docker/overlay2/d85f7cf20def119cbaad54078be5cdfa882284bc5be2ddb52330990486e55641-init/diff:/var/lib/docker/overlay2/8c83b36346afb47016a59a8ecd18c1e0e1ecd8cf85b6f3f4f07c051d864e9f93/diff:/var/lib/docker/overlay2/78c7097986814469e6dd0604d0eb5ae92715d5d3da1cbd2525abf1c78b23003a/diff:/var/lib/docker/overlay2/6e0e74616ea70f1df32bfd1779c10dbe69f8d4f4a643961113ba77f3f9a30f88/diff:/var/lib/docker/overlay2/d1aa53c2061daadd88130940e1e81fb0b409f6e3112d91950a5f27e37db25b2d/diff:/var/lib/docker/overlay2/2dd7adcad9281d851b601fa42690bd6263e51a0311768055878c180718aca963/diff:/var/lib/docker/overlay2/cc93b6479b36f400e8b77afef5bbb01d471f3513a78dfcf2755b4e67bb4b12b4/diff:/var/lib/docker/overlay2/6d1efc10653abb13b983e3a908bb8ceec3b1a83637e8918c98e2996f967558f2/diff:/var/lib/docker/overlay2/d4977d659e900e6a14f648a50b3b0441a27b110142cc48b9a33c24411ec6b479/diff:/var/lib/docker/overlay2/5c9bb6d6187ebc71d81f92d32ae2e56e06f3cc4fd2f0d40b9b5809249d8d1c6e/diff', 'MergedDir': '/var/lib/docker/overlay2/d85f7cf20def119cbaad54078be5cdfa882284bc5be2ddb52330990486e55641/merged', 'UpperDir': '/var/lib/docker/overlay2/d85f7cf20def119cbaad54078be5cdfa882284bc5be2ddb52330990486e55641/diff', 'WorkDir': '/var/lib/docker/overlay2/d85f7cf20def119cbaad54078be5cdfa882284bc5be2ddb52330990486e55641/work'}, 'Name': 'overlay2'}, 'Mounts': [{'Type': 'bind', 'Source': '/srv/wg-in/config', 'Destination': '/etc/wireguard', 'Mode': 'rw', 'RW': True, 'Propagation': 'rprivate'}], 'Config': {'Hostname': '73d499916475', 'Domainname': '', 'User': '', 'AttachStdin': False, 'AttachStdout': False, 'AttachStderr': False, 'ExposedPorts': {'51820/udp': {}, '51821/tcp': {}}, 'Tty': False, 'OpenStdin': False, 'StdinOnce': False, 'Env': ['WG_HOST=ofn.wg.josh.cafe', 'WG_PORT=48888', 'PASSWORD=testpassword', 'WG_DEFAULT_DNS=192.168.1.103, 192.168.1.189', 'WG_DEFAULT_ADDRESS=192.168.100.x', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'NODE_VERSION=14.18.1', 'YARN_VERSION=1.22.15', 'DEBUG=Server,WireGuard'], 'Cmd': ['/usr/bin/dumb-init', 'node', 'server.js'], 'Image': 'weejewel/wg-easy@sha256:79288cac4782dd9c37c2fc20d26eb663d2df9fa1d3a09b278d5c76411310ec0c', 'Volumes': {'/etc/wireguard': {}}, 'WorkingDir': '/app', 'Entrypoint': ['docker-entrypoint.sh'], 'OnBuild': None, 'Labels': {}}, 'NetworkSettings': {'Bridge': '', 'SandboxID': 'f38a10fd4125fe1f8115efeb2dd9366c29baf9614bd3e8aebefe998b11e2a1fe', 'HairpinMode': False, 'LinkLocalIPv6Address': '', 'LinkLocalIPv6PrefixLen': 0, 'Ports': {'51820/udp': [{'HostIp': '0.0.0.0', 'HostPort': '51820'}], '51821/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '51821'}]}, 'SandboxKey': '/var/run/docker/netns/f38a10fd4125', 'SecondaryIPAddresses': None, 'SecondaryIPv6Addresses': None, 'EndpointID': 'bb4fea7c4159ad4f5de82a8bc1fc1415d23a916e0d1d4a8df8487d4b170256ff', 'Gateway': '172.17.0.1', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'IPAddress': '172.17.0.2', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'MacAddress': '02:42:ac:11:00:02', 'Networks': {'bridge': {'IPAMConfig': None, 'Links': None, 'Aliases': None, 'NetworkID': 'dfbd02fb880c4b9cfb11191c395703e2fbd439d5d7a0953ba9dbd933713a1476', 'EndpointID': 'bb4fea7c4159ad4f5de82a8bc1fc1415d23a916e0d1d4a8df8487d4b170256ff', 'Gateway': '172.17.0.1', 'IPAddress': '172.17.0.2', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:11:00:02', 'DriverOpts': None}}}}
        c.ports = {'51820/udp': [{'HostIp': '0.0.0.0', 'HostPort': '51820'}], '51821/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '51821'}]}
        c.name = 'wg-in-test'

        img: MagicMock = MagicMock(spec=Image)
        img.attrs = {'Id': 'sha256:c90b263d8a383ac55905e4edbe1513ba87b1a479bcaa8bb471412137b9541751', 'RepoTags': [], 'RepoDigests': ['weejewel/wg-easy@sha256:79288cac4782dd9c37c2fc20d26eb663d2df9fa1d3a09b278d5c76411310ec0c'], 'Parent': '', 'Comment': 'buildkit.dockerfile.v0', 'Created': '2022-06-26T09:30:56.818800131Z', 'Container': '', 'ContainerConfig': {'Hostname': '', 'Domainname': '', 'User': '', 'AttachStdin': False, 'AttachStdout': False, 'AttachStderr': False, 'Tty': False, 'OpenStdin': False, 'StdinOnce': False, 'Env': None, 'Cmd': None, 'Image': '', 'Volumes': None, 'WorkingDir': '', 'Entrypoint': None, 'OnBuild': None, 'Labels': None}, 'DockerVersion': '', 'Author': '', 'Config': {'Hostname': '', 'Domainname': '', 'User': '', 'AttachStdin': False, 'AttachStdout': False, 'AttachStderr': False, 'ExposedPorts': {'51820/udp': {}, '51821/tcp': {}}, 'Tty': False, 'OpenStdin': False, 'StdinOnce': False, 'Env': ['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'NODE_VERSION=14.18.1', 'YARN_VERSION=1.22.15', 'DEBUG=Server,WireGuard'], 'Cmd': ['/usr/bin/dumb-init', 'node', 'server.js'], 'ArgsEscaped': True, 'Image': '', 'Volumes': None, 'WorkingDir': '/app', 'Entrypoint': ['docker-entrypoint.sh'], 'OnBuild': None, 'Labels': None}, 'Architecture': 'amd64', 'Os': 'linux', 'Size': 141586777, 'VirtualSize': 141586777, 'GraphDriver': {'Data': {'LowerDir': '/var/lib/docker/overlay2/78c7097986814469e6dd0604d0eb5ae92715d5d3da1cbd2525abf1c78b23003a/diff:/var/lib/docker/overlay2/6e0e74616ea70f1df32bfd1779c10dbe69f8d4f4a643961113ba77f3f9a30f88/diff:/var/lib/docker/overlay2/d1aa53c2061daadd88130940e1e81fb0b409f6e3112d91950a5f27e37db25b2d/diff:/var/lib/docker/overlay2/2dd7adcad9281d851b601fa42690bd6263e51a0311768055878c180718aca963/diff:/var/lib/docker/overlay2/cc93b6479b36f400e8b77afef5bbb01d471f3513a78dfcf2755b4e67bb4b12b4/diff:/var/lib/docker/overlay2/6d1efc10653abb13b983e3a908bb8ceec3b1a83637e8918c98e2996f967558f2/diff:/var/lib/docker/overlay2/d4977d659e900e6a14f648a50b3b0441a27b110142cc48b9a33c24411ec6b479/diff:/var/lib/docker/overlay2/5c9bb6d6187ebc71d81f92d32ae2e56e06f3cc4fd2f0d40b9b5809249d8d1c6e/diff', 'MergedDir': '/var/lib/docker/overlay2/8c83b36346afb47016a59a8ecd18c1e0e1ecd8cf85b6f3f4f07c051d864e9f93/merged', 'UpperDir': '/var/lib/docker/overlay2/8c83b36346afb47016a59a8ecd18c1e0e1ecd8cf85b6f3f4f07c051d864e9f93/diff', 'WorkDir': '/var/lib/docker/overlay2/8c83b36346afb47016a59a8ecd18c1e0e1ecd8cf85b6f3f4f07c051d864e9f93/work'}, 'Name': 'overlay2'}, 'RootFS': {'Type': 'layers', 'Layers': ['sha256:39982b2a789afc156fff00c707d0ff1c6ab4af8f1666a8df4787714059ce24e7', 'sha256:a303372b2caae8beec770cc39e25d3f8ef61d39bdd6ddfb35e408fc402b9cf96', 'sha256:b3031b5001d5acbb8e13c1ec54708914a524b6fff54c49a9e8968e9c9672f249', 'sha256:e763407a02c7e01cd850dd14d8332b6ea1fb8e5f3c016df96bf305ef0ad47826', 'sha256:159322f2828b0337b56c60a350c02bdc6444575fc50ab3c8684499db58e543b2', 'sha256:b7fb9f18b6d36619ec0c0a413320c02aa929d92628213d33ca3608c4e7d49800', 'sha256:83ef97c139857b0f3460a1fdbba93e527012de34b04899d101d9c5131f7e4b73', 'sha256:a8331a10795a20ba653f538f78fd41d1717dbde3a24a24db9cebe6402dde2a37', 'sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef']}, 'Metadata': {'LastTagTime': '0001-01-01T00:00:00Z'}}

        c.image = img

        dc: DockerContainer = n.docker.containers[0]

        for da in SUPPORTED_DOCKER_ATTRS:
            ours = da.from_necronomicon(dc)
            theirs = da.from_container(c)
            logging.info(f"{da.run_arg_name()}: o({ours}) t({theirs})")
            self.assertTrue(ours.is_satisfied_by(theirs), f"{da.run_arg_name()} should match but desired={ours} and found is {theirs}")


if __name__ == '__main__':
    unittest.main()
