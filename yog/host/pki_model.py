import os
import re
import typing as t
import yaml

from yog.model_utils import HostPathStr, parse_hostpath


class CAEntry(t.NamedTuple):
    ident: str
    storage: HostPathStr
    validity_period: str


def parse_validity_period(s: str) -> int:
    if s.endswith("y"):
        return 365 * int(s[:-1])
    elif s.endswith("d"):
        return int(s[:-1])
    else:
        raise ValueError(f"Invalid validity period: needs to end in y or d: {s}")


def load_caentry(raw: t.Any) -> CAEntry:
    return CAEntry(raw["ident"], parse_hostpath(raw["storage"]), str(raw["validity_period"]))


def load_cas(path: str) -> t.List[CAEntry]:
    with open(path, "r") as fin:
        raw = yaml.safe_load(fin.read())
    return [load_caentry(re) for re in raw]

