#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Encode/decodes AVM state into a Python dataclass."""

import dataclasses
from typing import cast

from pyteal import Bytes, Int, Expr, Addr


@dataclasses.dataclass
class AVMState:
    """
    Helper class that roughly maps a Python dataclass to the global state of
    a smart contract.
    """

    class UInt(int):
        """A `int` that will be encoded as a UInt in TEAL."""

    class Address(str):
        """A `str` that will be encoded as an address in TEAL."""

    class Bytes(bytes):
        """UTF-8 `bytes` that will be encoded as Bytes in TEAL."""

    @classmethod
    def field_to_key(cls, f: dataclasses.Field) -> str:
        """
        By default, fields are mapped to TEAL Bytes() with the same name.

        This function allows overriding this, e.g. to have more compact
        representation on-chain.
        """
        return f.name

    @classmethod
    def to_keys(cls, name):
        """Map dataclass field names into TEAL Bytes (for ASC state)."""
        return dataclasses.make_dataclass(
            name,
            [
                (
                    f.name,
                    Bytes,
                    cast(
                        dataclasses.Field,
                        dataclasses.field(default=Bytes(cls.field_to_key(f))),
                    ),
                )
                for f in dataclasses.fields(cls)
            ],
            frozen=True,
        )()

    def __str__(self):
        """Pretty print as a dictionary."""
        __import__("pprint").pformat(dataclasses.asdict(self))

    @classmethod
    def n_uints(cls):
        return sum(issubclass(f.type, int) for f in dataclasses.fields(cls))

    @classmethod
    def n_bytes(cls):
        """Anything that is not `int` will be encoded as bytes."""
        return len(dataclasses.fields(cls)) - cls.n_uints()

    def encode_to_avm(self, f: dataclasses.Field) -> Expr:
        """Encode given dataclass field for the AVM."""
        v = getattr(self, f.name)

        if issubclass(f.type, int):
            return Int(int(v))

        if issubclass(f.type, AVMState.Address):
            return Addr(str(v))

        if issubclass(f.type, AVMState.Bytes):
            return Bytes(bytes(v))

        # Default to Bytes
        return Bytes(v)
