import getpass
import typing as t
import logging
import os
import re
import subprocess
from hashlib import sha512
from random import randrange
from re import Pattern
from tempfile import NamedTemporaryFile
from time import sleep
from typing import Tuple, List, Optional, Set

from paramiko import SSHClient, PKey
import shlex

from yog.host.os_utils import Owner, RWXBits, Perms

log = logging.getLogger(__name__)


def _auto_shlex(cmd: t.Union[str, t.List[str]]):
    if isinstance(cmd, list):
        return " ".join(shlex.quote(a) for a in cmd)
    else:
        return cmd


def check_call(ssh: SSHClient, command: t.Union[str, t.List[str]], assert_stderr_empty: bool = False, send_stdin: Optional[t.AnyStr] = None, ):
    stdin, stdout, stderr = ssh.exec_command(_auto_shlex(command))
    if send_stdin is not None:
        stdin.write(send_stdin)
    stdin.close()
    rc = stdout.channel.recv_exit_status()

    if rc != 0:
        print(f"'{command}' returned exit code {rc}")
        _dump_lines("stdout", stdout.readlines())
        _dump_lines("stderr", stderr.readlines())
        raise NonzeroExitCodeError(rc)

    if assert_stderr_empty:
        stderr_contents = stderr.readlines()
        if stderr_contents:
            print(f"'{command}' expected empty stderr but it wasn't empty.")
            _dump_lines("stderr", stderr.readlines())
            raise StdErrNotEmptyError(stderr_contents)


def check_output(ssh: SSHClient, command: t.Union[str, t.List[str]], send_stdin: Optional[str] = None) -> Tuple[List[str], List[str]]:
    stdin, stdout, stderr = ssh.exec_command(_auto_shlex(command))
    if send_stdin is not None:
        stdin.write(send_stdin)

    rc = stdout.channel.recv_exit_status()

    if rc != 0:
        _dump_lines("stdout", stdout.readlines())
        _dump_lines("stderr", stderr.readlines())
        raise NonzeroExitCodeError(rc)

    return stdout.readlines(), stderr.readlines()


def check_code(ssh: SSHClient,
               command: t.Union[str, t.List[str]],
               assert_stderr_empty: bool = False,
               send_stdin: Optional[str] = None,
               assert_stdout_empty: bool = False
               ) -> bool:
    stdin, stdout, stderr = ssh.exec_command(_auto_shlex(command))
    if send_stdin is not None:
        stdin.write(send_stdin)
    rc = stdout.channel.recv_exit_status()

    if rc != 0:
        return False

    if assert_stderr_empty:
        stderr_contents = stderr.readlines()
        if stderr_contents:
            return False

    if assert_stdout_empty:
        stdout_contents = stdout.readlines()
        if stdout_contents:
            return False

    return True


def check_stdout(ssh: SSHClient, command: t.Union[str, t.List[str]]) -> t.List[str]:
    return check_output(ssh, command)[0]


def check_stderr(ssh: SSHClient, command: t.Union[str, t.List[str]]) -> t.List[str]:
    return check_output(ssh, command)[1]


def _dump_lines(title: str, lines: List[str]):
    print(f"--------------{title}------------")
    for line in lines:
        print(line)
    print("--------------------------------")


class NonzeroExitCodeError(Exception):
    code: int

    def __init__(self, code: int):
        self.code = code


class StdErrNotEmptyError(Exception):
    contents: List[str]

    def __init__(self, contents: List[str]):
        self.contents = contents


def get_host_key(ssh: SSHClient) -> PKey:
    return ssh.get_transport().get_remote_server_key()


def get_pids_binding_port(bound_port: int) -> Set[int]:
    lsof_lines = str(subprocess.check_output(["lsof", "-i", f":{bound_port}"]), encoding="utf-8")
    lsof_lines = lsof_lines.splitlines()[1:]
    lsof_lines = [re.split(r"\s+", str(l)) for l in lsof_lines]
    pids_bound = {int(l[1]) for l in lsof_lines if l[4] == "IPv4"}
    return pids_bound


# always prints:
# debug1: Local forwarding listening on 127.0.0.1 port 44444.
# this means success:
# debug1: channel 0: new [port listener]

success_pattern: Pattern = re.compile(r"^(debug1: channel \d+: new \[port listener])|(debug1: remote forward success for: listen \d+, connect localhost:\d+)|(debug1: channel \d+: new port-listener \[port listener\] \(inactive timeout: \d+\))$")


def _render_cmd(rand_port, prefix, host, forward_flag, expr):
    return prefix + ["ssh", "-v", "-4", "-o", "ExitOnForwardFailure=yes",
                     "-N", forward_flag, expr.format(rand_port),
                     host]

# 2 bugs:
# * stderr will keep printing but i've stopped reading it. This will cause a deadlock eventually. fix by just moving to
#  a new thread and babysitting stderr there
# * when proxying, remote ssh process doesn't die when local ssh process dies. this keeps the port bound.

# crazy idea: fuck asyncio, fuck threads, etc. Popen(bash -c ssh 2>/tmp/namedtmpfile) and then fucking read
# the tempfile over and over till I find my shit.


class ScopedProxiedRemoteSSHTunnel:
    proxy_host: Optional[str]
    host: str
    port_forwarded: int
    forward_type: str

    proc: Optional[subprocess.Popen]

    def __init__(self, host: str,
                 port_forwarded: int,
                 proxy_host: Optional[str] = None,
                 forward_type: str = "local",
                 force_random_port: int = None):
        self.host = host
        self.port_forwarded = port_forwarded
        self.proxy_host = proxy_host
        self.forward_type = forward_type
        self.force_random_port = force_random_port

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def connect(self) -> int:
        if self.forward_type == "local":
            forward_flag = "-L"
            forward_expr = f"{{}}:localhost:{self.port_forwarded}"
        elif self.forward_type == "remote":
            forward_flag = "-R"
            forward_expr = f"{self.port_forwarded}:localhost:{{}}"
        else:
            raise ValueError(f"Illegal value for forward_type: \"{self.forward_type}\" must be one of local, remote")

        if self.proxy_host is not None:
            cmd_prefix = ["ssh", "-t", "-t", self.proxy_host]
        else:
            cmd_prefix = []

        self.proc, rport = _setup_tunnel(cmd_prefix, self.host, forward_flag, forward_expr, self.force_random_port)
        return rport

    def disconnect(self):
        if self.proc is not None:
            self.proc.kill()
            log.debug(f"SSH tunnel ended.")


def _setup_tunnel(cmd_prefix, host, forward_flag, forward_expr, force_random_port=None) -> Tuple[subprocess.Popen, int]:
    tries = 25
    port = None
    proc = None
    while tries > 0 and proc is None:
        if force_random_port is None:
            port = randrange(1024, 65535 + 1)
        else:
            port = force_random_port
        cmd = _render_cmd(port, cmd_prefix, host, forward_flag, forward_expr)
        stderr_file = NamedTemporaryFile("w", delete=False)
        stdout_file = NamedTemporaryFile("w", delete=False)
        try:
            proc = _try_setup_tunnel(port, cmd, stdout_file, stderr_file)
        except RuntimeError as e:
            log.info(f"SSH tunnel open threw exception. Tries left: {tries}", exc_info=e)
            tries -= 1
        finally:
            os.remove(stderr_file.name)
            os.remove(stdout_file.name)

    if proc is None:
        log.error(f"Gave up. Couldn't open ssh tunnel.")
        raise RuntimeError(f"Couldn't open SSH tunnel.")

    if port is None:
        raise RuntimeError("port was none. this should never happen.")
    return proc, port


def _try_setup_tunnel(port: int, cmd: List[str], stdout_file: NamedTemporaryFile, stderr_file: NamedTemporaryFile) -> Optional[subprocess.Popen]:
    proc = subprocess.Popen(cmd, stdout=stdout_file, stderr=stderr_file, stdin=subprocess.PIPE)
    confirmed = False
    timeout = 10.0
    while not (confirmed or proc.returncode is not None) and timeout > 0:
        sleep(0.1)
        timeout -= 0.1
        for fobj in [stdout_file, stderr_file]:
            fobj.flush()
            with open(fobj.name, "r") as fin:
                for line in fin:
                    if success_pattern.match(line.strip()):
                        confirmed = True

    if not confirmed:
        outputs = []
        for fileobj in [stdout_file, stderr_file]:
            with open(fileobj.name, "r") as fin:
                outputs.append(fin.read())
        stderr = "\n".join(outputs)
        if "Address already in use" in stderr:
            log.info(f"Port {port} already in use.")
        else:
            log.error(f"SSH tunnel didn't stay open. Weird.")
            log.error("--------------ssh stderr-------------------")
            log.error(stderr)
            log.error("--------------end ssh stderr---------------")
        return None
    else:
        log.debug(f"SSH tunnel started.")
        return proc


def compare_local_and_remote(body: bytes, remote_path: str, ssh: SSHClient, root: bool = False):
    expected: str = sha512(body).hexdigest()
    remote_path = shlex.quote(remote_path)

    found: Optional[str]
    if check_code(ssh, f"{'sudo ' if root else ''}test -f \"{remote_path}\""):
        found: str = re.split(r"\s+", check_output(ssh, f"{'sudo ' if root else ''}sha512sum \"{remote_path}\"")[0][0], 1)[0]
    else:
        found = None

    return expected == found, expected, found


def cat(ssh: SSHClient, path: str, root: bool = False) -> str:
    log.debug(f"cat {path}")
    prefix = 'sudo ' if root else ''
    path = shlex.quote(path)
    cmd = prefix + f"cat {path}"
    return "".join(check_stdout(ssh, cmd))


def mkdirp(ssh: SSHClient, path: str, user: str = None):
    log.debug(f"mkdir -p {path}")
    path = shlex.quote(path)
    cmd = f"mkdir -p {path}"
    cmd = _as_user(cmd, user)
    check_call(ssh, cmd)


def stat(ssh: SSHClient, path: str) -> t.Tuple[Owner, Perms]:
    path = shlex.quote(path)
    # stat -c '%A %U:%G'
    raw = check_output(ssh, f"stat -c {shlex.quote('%A %U:%G')} {path}")[0][0].strip()
    log.debug(f"stat: {path}: {raw}")
    perms, owner = raw.split(" ", 1)
    perms = perms[-9:]

    return Owner.from_str(owner), Perms(*RWXBits.from_stat(perms))


def _as_user(cmd: str, user: t.Optional[str]) -> str:
    user = shlex.quote(user)
    if user is None:
        return cmd
    elif user == "root":
        return "sudo " + cmd
    else:
        return f"sudo -u {user} {cmd}"


def exists(ssh: SSHClient, path: str) -> bool:
    log.debug(f"exists? {path}")
    path = shlex.quote(path)
    ret = check_code(ssh, f"test -e {path}")
    log.debug(f"exists? {path} = {ret}")
    return ret


def put(ssh: SSHClient, path: str, content: t.AnyStr, user: t.Optional[str] = None, group: t.Optional[str]=None, mode: t.Optional[str] = "644"):
    log.debug(f"put {path} {user}:{group} {mode}")
    mode = shlex.quote(mode)
    path = shlex.quote(path)

    install_opts = [f"-m {mode}"]
    if user:
        user = shlex.quote(user)
        install_opts.append(f"-o {user}")
    if group:
        group = shlex.quote(group)
        install_opts.append(f"-g {group}")
    check_call(ssh, _as_user(f"install {' '.join(install_opts)} /dev/null {path}", "root"))

    subcommand = shlex.quote(f"cat - > {path}")
    check_call(ssh, _as_user(f"bash -c {subcommand}", "root"), send_stdin=content)
