"""The type map (Technical Spec 9.13): how each engine's native types are compared.

typemap.yaml, versioned and shipped with the package, holds the default canonical type
of each native type per engine, the alternatives a project may compare one as, and the
pairs of canonical types that compare as one. A project overrides it per engine under
database.type_map, only with those alternatives: each renders alike in the database and
in the reference implementation, which the parity tests prove. Baselines, a run's
checkpoint and its report record the version, the overrides and, per engine, a
fingerprint of the mapping that applied.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from importlib import resources
from typing import Any

import yaml

from liftproof.canonical.types import CanonicalType
from liftproof.errors import ConfigError

MYSQL_HEAD = re.compile(r"([a-z]+)(\([^)]*\))?")
ORACLE_NUMBER = re.compile(r"number\((\d+|\*)(?:,(-?\d+))?\)")
ARGUMENTS = re.compile(r"\([^)]*\)")


def type_keys(engine: str, native: str) -> tuple[str, ...]:
    """The keys a native type is looked up by, most specific first, each lower case with
    single spaces: the whole type, then (MySQL) the type with its arguments but without
    modifiers, or (Oracle) the class of a NUMBER, then the type without arguments."""
    full = " ".join(str(native).lower().split())
    if engine == "mysql":
        head = MYSQL_HEAD.match(full)  # 'tinyint(1) unsigned': 'tinyint(1)', 'tinyint'
        keys = [full, head[0], head[1]] if head else [full]
    else:
        keys = [full]
        number = ORACLE_NUMBER.fullmatch(full) if engine == "oracle" else None
        if number:
            p, s = number.groups()
            if s == "0":  # the adapter shows NUMBER(p,0) as NUMBER(p), NUMBER(*,0) as INTEGER
                keys = ["integer" if p == "*" else f"number({p})"]
            if s is not None and int(s) > 0:
                keys.append("number(p,s)")
            elif p != "*" or s is not None:
                keys.append("number(p)")
        keys.append(" ".join(ARGUMENTS.sub("", full).split()))
    return tuple(dict.fromkeys(keys))


@dataclass(frozen=True)
class TypeRule:
    canonical: CanonicalType  # the default
    also: tuple[CanonicalType, ...] = ()  # the alternatives a project may choose


@dataclass(frozen=True)
class TypeMap:
    version: str
    engines: dict[str, dict[str, TypeRule]]
    compatible: tuple[tuple[frozenset[CanonicalType], CanonicalType], ...]
    # the project's: engine -> key -> canonical type
    overrides: dict[str, dict[str, CanonicalType]] = field(default_factory=dict)

    @classmethod
    def shipped(cls) -> TypeMap:
        text = resources.files(__package__).joinpath("typemap.yaml").read_text(encoding="utf-8")
        return cls.parse(yaml.safe_load(text))

    @classmethod
    def parse(cls, d: dict[str, Any]) -> TypeMap:
        """A type map file. Malformed is a ValueError, so a broken shipped file fails at
        import and in the tests."""
        version = d.get("version")
        if not isinstance(version, str) or not version:
            raise ValueError("type map: version is missing")
        engines: dict[str, dict[str, TypeRule]] = {}
        for engine, entries in d["engines"].items():
            rules = engines[engine] = {}
            for key, entry in entries.items():
                if isinstance(entry, str):
                    entry = {"canonical": entry}
                rule = TypeRule(
                    CanonicalType(entry["canonical"]),
                    tuple(CanonicalType(t) for t in entry.get("also", ())),
                )
                types = (rule.canonical, *rule.also)
                if len(set(types)) < len(types) or CanonicalType.UNSUPPORTED in types:
                    raise ValueError(f"type map {engine}.{key}: {types} repeats or is unsupported")
                if type_keys(engine, key)[0] != key:
                    raise ValueError(f"type map {engine}.{key}: write keys as type_keys does")
                rules[key] = rule
        compatible = []
        for pair in d.get("compatible", []):
            types = frozenset(CanonicalType(t) for t in pair["types"])
            common = CanonicalType(pair["as"])
            if len(types) != 2 or common not in types:
                raise ValueError(f"type map compatible {pair}: two types, as one of them")
            compatible.append((types, common))
        return cls(version, engines, tuple(compatible))

    def rule(self, engine: str, native: str) -> TypeRule | None:
        """The default entry for a native type: that of its most specific key."""
        rules = self.engines.get(engine, {})
        return next((rules[k] for k in type_keys(engine, native) if k in rules), None)

    def default(self, engine: str, native: str) -> CanonicalType:
        rule = self.rule(engine, native)
        return rule.canonical if rule else CanonicalType.UNSUPPORTED

    def canonical(self, engine: str, native: str) -> CanonicalType:
        """What a column of this native type is compared as: at each key, most specific
        first, the project's override, then the default. A more specific default so beats
        a less specific override."""
        rules = self.engines.get(engine, {})
        overrides = self.overrides.get(engine, {})
        for key in type_keys(engine, native):
            if key in overrides:
                return overrides[key]
            if key in rules:
                return rules[key].canonical
        return CanonicalType.UNSUPPORTED

    def common(self, a: CanonicalType, b: CanonicalType) -> CanonicalType | None:
        """The type two different canonical types compare as, if they are compatible."""
        return next((c for types, c in self.compatible if {a, b} <= types), None)

    def with_overrides(self, given: Any, engines: set[str]) -> TypeMap:
        """This map with a project's database.type_map: per engine of the project, a native
        type as the report shows it and one of the alternatives this map lists for it."""
        where = "database.type_map"
        if not isinstance(given, dict) or not all(isinstance(v, dict) for v in given.values()):
            raise ConfigError(
                f"{where} maps an engine ({', '.join(self.engines)}) to "
                "{native type: canonical type}"
            )
        overrides: dict[str, dict[str, CanonicalType]] = {}
        for engine, types in given.items():
            if engine not in self.engines:
                raise ConfigError(f"{where}.{engine}: not an engine ({', '.join(self.engines)})")
            if engine not in engines:
                raise ConfigError(
                    f"{where}.{engine}: neither the source nor the target is {engine}"
                )
            for native, ctype in types.items():
                path = f"{where}.{engine}.{native}"
                key = type_keys(engine, str(native))[0]
                rule = self.rule(engine, key)
                if rule is None:
                    raise ConfigError(
                        f"{path}: not a {engine} type in type map {self.version}; give the "
                        "native type as the report shows it"
                    )
                allowed = [str(t) for t in (rule.canonical, *rule.also)]
                if str(ctype) not in allowed:
                    raise ConfigError(
                        f"{path}: {native} is compared as {' or '.join(allowed)} in type map "
                        f"{self.version}, not {ctype}"
                    )
                overrides.setdefault(engine, {})[key] = CanonicalType(str(ctype))
        return replace(self, overrides=overrides)

    def fingerprint(self, engine: str) -> str:
        """What decides how the engine's columns compare: its defaults, the project's
        overrides and the compatible pairs. Not the version, the alternatives allowed or
        another engine's entries, which change nothing for this one."""
        mapping = {
            "defaults": {k: str(r.canonical) for k, r in self.engines.get(engine, {}).items()},
            "overrides": {k: str(c) for k, c in self.overrides.get(engine, {}).items()},
            "compatible": sorted([*sorted(map(str, t)), str(c)] for t, c in self.compatible),
        }
        text = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

    def record(self, *engines: str) -> dict[str, Any]:
        """What a baseline, a run's checkpoint and a report keep: the version, the
        overrides and, per engine, the fingerprint of the mapping that applied."""
        engines = tuple(sorted(set(engines)))
        return {
            "version": self.version,
            "overrides": {
                e: {k: str(c) for k, c in sorted(self.overrides[e].items())}
                for e in engines
                if self.overrides.get(e)
            },
            "fingerprints": {e: self.fingerprint(e) for e in engines},
        }


DEFAULT_TYPE_MAP = TypeMap.shipped()

# Manifests and checkpoints written before the type map was recorded were taken under the
# adapters' maps of the time, which version 1.0 reproduces, with no overrides.
V1_FINGERPRINTS = {
    "postgresql": "30280e4210c18d62",
    "mysql": "b667dd9ae89cb15b",
    "oracle": "c9f441c5f4bb6566",
    "sqlserver": "bbdda6ff3f907dee",
}


def legacy_record(*engines: str) -> dict[str, Any]:
    engines = tuple(sorted(set(engines)))
    return {
        "version": "1.0",
        "overrides": {},
        "fingerprints": {e: V1_FINGERPRINTS[e] for e in engines},
    }


def shown(record: dict[str, Any]) -> str:
    """A record in words: its version and overrides."""
    overrides = [
        f"{e} {k} as {c}" for e, types in record["overrides"].items() for k, c in types.items()
    ]
    return f"type map {record['version']} " + (
        f"with {', '.join(overrides)}" if overrides else "without overrides"
    )
