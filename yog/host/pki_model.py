import os
import typing as t
import yaml

from yog.model_utils import HostPathStr, parse_hostpath

class CAEntry(t.NamedTuple):
    ident: str
    storage: HostPathStr
    validity_years: int


def load_caentry(raw: t.Any) -> CAEntry:
    return CAEntry(raw["ident"], parse_hostpath(raw["storage"]), int(raw["validity_years"]))

def load_cas(path: str) -> t.List[CAEntry]:
    with open(path, "r") as fin:
        raw = yaml.safe_load(fin.read())
    return [load_caentry(re) for re in raw]

