import typing as t


class RWXBits(t.NamedTuple):
    read: bool
    write: bool
    execute: bool

    @staticmethod
    def from_str(str_repr: str) -> 'RWXBits':
        return RWXBits("r" in str_repr, "w" in str_repr, "x" in str_repr)

    @staticmethod
    def from_stat(stat_str: str) -> t.Tuple['RWXBits', 'RWXBits', 'RWXBits']:
        return (
            RWXBits.from_str(stat_str[0:3]),
            RWXBits.from_str(stat_str[3:6]),
            RWXBits.from_str(stat_str[6:9]),
        )

    def to_octal_digit(self) -> str:
        sum = 0
        if self.read:
            sum += 4
        if self.write:
            sum += 2
        if self.execute:
            sum += 1

        return str(sum)


class Owner(t.NamedTuple):
    user: str
    group: str

    @staticmethod
    def from_str(s: str) -> 'Owner':
        return Owner(*s.split(":", 1))


class Perms(t.NamedTuple):
    u: RWXBits
    g: RWXBits
    o: RWXBits

    def to_chmod_expr(self) -> str:
        return "".join(p.to_octal_digit() for p in [self.u, self.g, self.o])
