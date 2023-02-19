import typing as t

class HostPathStr(t.NamedTuple):
    host: str
    path: str

def parse_hostpath(s: str) -> HostPathStr:
    split = s.split(":")
    if len(split) != 2:
        raise ValueError(f"HostPath \"{s}\" must be of format host:path")

    if not split[1].startswith("/"):
        raise ValueError(f"HostPath \"{s}\" must be an absolute path.")

    return HostPathStr(*split)