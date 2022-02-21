#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Poor man ABI.

This will likely be dropped when PyTeal will include proper ABI support,
ie in https://github.com/algorand/pyteal/pull/154 and friends.
"""

import dataclasses
import functools
import inspect
from typing import Optional
from Cryptodome.Hash import SHA512

from pyteal import (
    Btoi,
    Bytes,
    Expr,
    Int,
    Txn,
)


class ABI:

    """
    This class implements ARC-0004 ABI helpers, encoders and decoders.

    https://github.com/algorandfoundation/ARCs/blob/main/ARCs/arc-0004.md
    """

    ON_CALL_NUM_APP_ARGS = 1  # ARC-4 ABI: Selector.
    DISPATCH_TABLE = {}  # Maps selectors to decorated Python functions (the methods).
    RETURN_PREFIX = Bytes("base16", "0x151f7c75")  # Literally hash('return')[:4]

    TRUE = 0x80
    FALSE = 0x0

    @dataclasses.dataclass(frozen=True)
    class Arg:
        name: str
        type: str
        desc: Optional[str] = None

        @classmethod
        def parse(cls, arg: dict) -> "ABI.Arg":
            return cls(name=arg["name"], type=arg["type"], desc=arg.get("desc"))

    class Args(list["ABI.Arg"]):
        # Allow interface.args.arg_name
        def __getattr__(self, name):
            for e in self:
                if e.name == name:
                    return e
            raise KeyError

    @dataclasses.dataclass(frozen=True)
    class Returns:
        type: str
        desc: Optional[str] = None

        @classmethod
        def parse(cls, returns: dict) -> "ABI.Returns":
            return cls(type=returns["type"], desc=returns.get("desc"))

    @dataclasses.dataclass(frozen=True)
    class Interface:
        name: str
        args: "ABI.Args"
        raw: dict
        returns: "ABI.Returns"
        desc: Optional[str] = None

        @classmethod
        def parse(cls, interface: dict) -> "ABI.Interface":
            name = interface["name"]
            args = ABI.Args([ABI.Arg.parse(a) for a in interface["args"]])
            returns = ABI.Returns.parse(interface["returns"])

            return cls(
                name=name,
                args=args,
                raw=interface,
                returns=returns,
                desc=interface.get("desc"),
            )

        @property
        def num_accounts(self):
            return sum(a.type == "account" for a in self.args)

        @property
        def num_assets(self):
            return sum(a.type == "asset" for a in self.args)

        @property
        def num_app_args(self):
            return ABI.ON_CALL_NUM_APP_ARGS + len(self.args)

    @staticmethod
    def abi_interface_to_signature(interface: Interface) -> str:
        args = f"{','.join(a.type for a in interface.args)}"
        selector = f"{interface.name}({args}){interface.returns.type if interface.returns else 'void'}"
        return selector

    @staticmethod
    def signature_to_selector(signature: str) -> bytes:
        hash = SHA512.new(truncate="256")
        hash.update(signature.encode("utf-8"))
        return hash.digest()[:4]

    @staticmethod
    def to_contract_specification(
        b64_genesis_id: str, app_id: int, additional_info: Optional[dict] = None
    ) -> dict:
        """Export full ABI contract specification as `dict`."""
        d = {}
        d["name"] = "TC-ASA"
        network_info = {"appID": app_id}
        if additional_info:
            network_info.update(additional_info)
        d["networks"] = {b64_genesis_id: network_info}
        d["methods"] = [m.interface.raw for m in ABI.DISPATCH_TABLE.values()]
        return d

    class TealArgs(dict[str, Expr]):
        def __getattr__(self, name) -> Expr:
            # Allow args.arg_name
            return self[name]

    @staticmethod
    def args_to_teal(iface: Interface) -> TealArgs:
        teal_args = {}

        for i, arg in enumerate(iface.args):
            # We need to add `1` to `i` because of the selector argument.
            i_plus_one, name = Int(i + 1), arg.name
            # TODO: This doesn't work with group txns for now.

            current_arg = Txn.application_args[i_plus_one]
            if arg.type.startswith("uint") or arg.type == "bool":
                teal_args[name] = Btoi(current_arg)
            elif arg.type == "account":
                teal_args[name] = Txn.accounts[Btoi(current_arg)]
            elif arg.type == "asset":
                teal_args[name] = Txn.assets[Btoi(current_arg)]
            # elif arg.type == "string":
            #     teal_args[name] = Substring(current_arg, Int(2), Len(current_arg))
            else:
                # Default.
                teal_args[name] = Txn.application_args[i_plus_one]

        return ABI.TealArgs(teal_args)

    @staticmethod
    def method(iface: dict):
        """
        Decorator to mark a Python function (returning a TEAL expression) as an
        ABI method.
        """
        interface = ABI.Interface.parse(iface)
        signature = ABI.abi_interface_to_signature(interface)
        selector = ABI.signature_to_selector(signature)

        def decorator_abi_method(func):
            @functools.wraps(func)
            def wrapper_abi_method(*_args, **_kwargs):
                kwargs = {}
                signature = inspect.signature(func)

                if "args" in signature.parameters:
                    kwargs["args"] = ABI.args_to_teal(interface)
                if "iface" in signature.parameters:
                    kwargs["iface"] = interface

                # Adds the `iface` argument and the teal arguments.
                return func(*_args, **kwargs, **_kwargs)

            wrapper_abi_method.interface = interface
            wrapper_abi_method.signature = signature
            wrapper_abi_method.selector = selector
            # NOTE: Consider moving this to an instance variable.
            wrapper_abi_method.asc_id = None
            ABI.DISPATCH_TABLE[selector] = wrapper_abi_method
            return wrapper_abi_method

        return decorator_abi_method
