#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Transfer-controlled Algorand Standard Asset (ASA).

Ties an ASA to an ASC (Algorand Smart Contract) and exposes methods to
mint/burn/transfer.

Allows providing custom logic around transfers.
"""

import dataclasses

from pyteal import (
    And,
    App,
    Approve,
    Assert,
    AssetHolding,
    Bytes,
    Cond,
    Expr,
    Global,
    InnerTxnBuilder,
    Int,
    Mode,
    Not,
    OnComplete,
    Or,
    Reject,
    Seq,
    Txn,
    TxnField,
    TxnType,
    compileTeal,
)
from pyteal.ast.asset import AssetParam

from state import AVMState
from abi import ABI

TEAL_VERSION = 5


@dataclasses.dataclass
class Config(AVMState):
    master: AVMState.Address  # Master address (can be multi-sig)

    # The asset may be globally "frozen", no transfers will be approved until it is "unfrozen".
    is_frozen: AVMState.UInt = AVMState.UInt(0)

    # Corresponding ASA token
    asa: AVMState.UInt = AVMState.UInt(0)  # Wil be set by `initializeReserves`


@dataclasses.dataclass
class LocalConfig(AVMState):
    is_locked: AVMState.UInt = AVMState.UInt(0)
    is_whitelisted: AVMState.UInt = AVMState.UInt(0)


Keys = Config.to_keys_factory("Keys")()
LocalKeys = LocalConfig.to_keys_factory("LocalKeys")()


TC_ASA_RESERVE = Global.current_application_address()


UNLOCKED = Int(ABI.FALSE)
LOCKED = Int(ABI.TRUE)
LOCK_INTERFACE = {
    "name": "setLock",
    "args": [
        {"name": "user", "type": "account", "desc": "User to lock/unlock."},
        {
            "name": "isLocked",
            "type": "bool",
            "desc": "Lock (`true`) / unlock (`false`).",
        },
    ],
    "returns": {"type": "void"},
}


@ABI.method(LOCK_INTERFACE)
def set_lock_unlock(args: ABI.TealArgs) -> Expr:
    """
    Specific users may be "locked" by `master` so that they cannot transfer
    their tokens without being "unlocked first".
    """
    is_locked_arg = args.isLocked
    precondition = And(
        is_master(Txn.sender()),
        Or(  # Pedantic
            is_locked_arg == UNLOCKED,
            is_locked_arg == LOCKED,
        ),
        Not(App.localGet(args.user, LocalKeys.is_locked) == is_locked_arg),
    )

    return Seq(
        Assert(precondition),
        # Lock user (account #1)
        App.localPut(args.user, LocalKeys.is_locked, is_locked_arg),
        Approve(),
    )


def _is_locked(account: Expr) -> Expr:
    return App.localGet(account, LocalKeys.is_locked) == LOCKED


NOT_WHITELISTED = Int(ABI.FALSE)
WHITELISTED = Int(ABI.TRUE)
WHITELIST_INTERFACE = {
    "name": "setWhitelist",
    "args": [
        {"name": "user", "type": "account", "desc": "User to whitelist."},
        {
            "name": "isWhitelisted",
            "type": "bool",
            "desc": "Whitelist (`true`) / remove whitelist (`false`).",
        },
    ],
    "returns": {"type": "void"},
}


@ABI.method(WHITELIST_INTERFACE)
def set_whitelist(args: ABI.TealArgs) -> Expr:
    """
    Whitelist a user.
    """
    whitelist_arg = args.isWhitelisted
    precondition = And(
        is_master(Txn.sender()),
        Or(  # Pedantic
            whitelist_arg == NOT_WHITELISTED,
            whitelist_arg == WHITELISTED,
        ),
        Not(App.localGet(args.user, LocalKeys.is_whitelisted) == whitelist_arg),
    )

    return Seq(
        Assert(precondition),
        # Whitelist user (account #1)
        App.localPut(args.user, LocalKeys.is_whitelisted, whitelist_arg),
        Approve(),
    )


def _is_whitelisted(account: Expr) -> Expr:
    return App.localGet(account, LocalKeys.is_whitelisted) == WHITELISTED


NOT_FROZEN = Int(ABI.FALSE)
FROZEN = Int(ABI.TRUE)
FREEZE_INTERFACE = {
    "name": "setFreeze",
    "args": [
        {
            "name": "isFrozen",
            "type": "bool",
            "desc": "Frozen (`true`) / not frozen (`false`).",
        },
    ],
    "returns": {"type": "void"},
}


@ABI.method(FREEZE_INTERFACE)
def set_freeze_unfreeze_token(args: ABI.TealArgs) -> Expr:
    """
    The asset may be "frozen" by `master`, at which point no transfers will be
    approved until it is "unfrozen".
    """
    freeze_arg = args.isFrozen

    precondition = And(
        is_master(Txn.sender()),
        Or(  # Pedantic
            freeze_arg == NOT_FROZEN,
            freeze_arg == FROZEN,
        ),
        Not(App.globalGet(Keys.is_frozen) == freeze_arg),
    )

    return Seq(
        Assert(precondition),
        App.globalPut(Keys.is_frozen, freeze_arg),
        Approve(),
    )


def _is_frozen():
    return App.globalGet(Keys.is_frozen) == FROZEN


def is_master(account: Expr) -> Expr:
    """
    Check whether the provided `account` is the `master`.
    """
    return account == App.globalGet(Keys.master)


MINT_INTERFACE = {
    "name": "mint",
    "args": [
        {
            "name": "user",
            "type": "account",
            "desc": "The user that will receive the funds.",
        },
        {
            "name": "amount",
            "type": "uint64",
            "desc": "Amount of funds to mint to the user.",
        },
        {
            "name": "asset",
            "type": "asset",
            "desc": "Reference to the ASA controlled by this smart contract.",
        },
    ],
    "returns": {"type": "void"},
}


@ABI.method(MINT_INTERFACE)
def mint(args: ABI.TealArgs) -> Expr:
    """
    `master` can mint new tokens into circulation.

    The `user` receiving the funds must be `whitelisted` and the asset must NOT
    be `frozen`.
    """
    asset = args.asset
    is_tc_asa = asset_is_tc_asa(asset)

    user = args.user
    amount = args.amount
    positive_amount = amount > Int(0)

    token_is_not_frozen = Not(_is_frozen())
    user_is_whitelisted = _is_whitelisted(args.user)

    precondition = And(
        is_master(Txn.sender()),
        is_tc_asa,
        positive_amount,
        token_is_not_frozen,
        user_is_whitelisted,
    )

    tc_asa_mint = [
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.AssetTransfer),
        InnerTxnBuilder.SetField(TxnField.xfer_asset, App.globalGet(Keys.asa)),
        InnerTxnBuilder.SetField(TxnField.asset_amount, amount),
        InnerTxnBuilder.SetField(TxnField.asset_receiver, user),
        InnerTxnBuilder.SetField(TxnField.asset_sender, TC_ASA_RESERVE),
        # TODO: Fees?
        InnerTxnBuilder.Submit(),
    ]

    return Seq(
        Assert(precondition),
        *tc_asa_mint,
        Approve(),
    )


BURN_INTERFACE = {
    "name": "burn",
    "args": [
        {
            "name": "user",
            "type": "account",
            "desc": "Funds will be burned from this user's balance.",
        },
        {
            "name": "amount",
            "type": "uint64",
            "desc": "Amount of funds to burn.",
        },
        {
            "name": "asset",
            "type": "asset",
            "desc": "Reference to the ASA controlled by this smart contract.",
        },
    ],
    "returns": {"type": "void"},
}


@ABI.method(BURN_INTERFACE)
def burn(args: ABI.TealArgs) -> Expr:
    """
    `master` can transfer from a user back to the treasury.
    """
    asset = args.asset
    user = args.user
    amount = args.amount
    is_tc_asa = asset_is_tc_asa(asset)

    positive_amount = amount > Int(0)

    precondition = And(
        is_master(Txn.sender()),
        is_tc_asa,
        positive_amount,
    )

    tc_asa_burn = [
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.AssetTransfer),
        InnerTxnBuilder.SetField(TxnField.xfer_asset, App.globalGet(Keys.asa)),
        InnerTxnBuilder.SetField(TxnField.asset_amount, amount),
        InnerTxnBuilder.SetField(TxnField.asset_sender, user),
        InnerTxnBuilder.SetField(TxnField.asset_receiver, TC_ASA_RESERVE),
        # TODO: Fees?
        InnerTxnBuilder.Submit(),
    ]

    return Seq(
        Assert(precondition),
        *tc_asa_burn,
        Approve(),
    )


TRANSFER_INTERFACE = {
    "name": "transfer",  # TC-ASA standard.
    "args": [
        {
            "name": "receiver",
            "type": "account",
            "desc": "The user that will receive the funds.",
        },
        {
            "name": "amount",
            "type": "uint64",
            "desc": "Amount of funds to transfer to the user.",
        },
        {
            "name": "asset",
            "type": "asset",
            "desc": "Reference to the ASA controlled by this smart contract.",
        },
    ],
    "returns": {"type": "void"},
}


@ABI.method(TRANSFER_INTERFACE)
def transfer(args: ABI.TealArgs) -> Expr:
    """Controlled transfer of the underlying ASA from `Transaction.Sender` to `user`."""
    asset = args.asset
    is_tc_asa = asset_is_tc_asa(asset)

    receiver = args.receiver
    amount = args.amount
    positive_amount = amount > Int(0)

    no_self_payment = Txn.sender() != receiver

    token_is_not_frozen = Not(_is_frozen())

    sender_is_not_locked = Not(_is_locked(Txn.sender()))

    sender_has_enough_balance = Seq(  # pedantic, the ASA clawback will underflow if not
        sender_asset_balance := AssetHolding.balance(Txn.sender(), asset),
        sender_asset_balance.value() - amount >= Int(0),
    )

    sender_is_whitelisted = _is_whitelisted(Txn.sender())
    receiver_is_whitelisted = _is_whitelisted(receiver)

    precondition = And(
        is_tc_asa,
        positive_amount,
        no_self_payment,
        token_is_not_frozen,
        sender_is_not_locked,
        sender_has_enough_balance,
        sender_is_whitelisted,
        receiver_is_whitelisted,
    )

    tc_asa_transfer = [
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.AssetTransfer),
        InnerTxnBuilder.SetField(TxnField.xfer_asset, App.globalGet(Keys.asa)),
        InnerTxnBuilder.SetField(TxnField.asset_amount, amount),
        InnerTxnBuilder.SetField(TxnField.asset_receiver, receiver),
        InnerTxnBuilder.SetField(TxnField.asset_sender, Txn.sender()),
        # TODO: Fees?
        InnerTxnBuilder.Submit(),
    ]

    return Seq(
        Assert(precondition),
        *tc_asa_transfer,
        Approve(),
    )


def asset_is_tc_asa(e: Expr) -> Expr:
    """Check that provided asset is the TC-ASA handled by this contract."""
    return e == App.globalGet(Keys.asa)


INITIALIZE_RESERVES_INTERFACE = {
    "name": "initializeReserves",
    "desc": "This method allows transferring the TC-ASA and role ASA reserves into the ASC.",
    "args": [
        {
            "name": "asset",
            "type": "asset",
            "desc": "Reference to the ASA controlled by this smart contract.",
        },
    ],
    "returns": {"type": "void"},
}


@ABI.method(INITIALIZE_RESERVES_INTERFACE)
def initialize_reserves(args: ABI.TealArgs):
    current_app_address = Global.current_application_address()
    precondition = And(
        is_master(Txn.sender()),
        App.globalGet(Keys.asa) == Int(0),  # This prevents double initialization.
    )
    return Seq(
        Assert(precondition),
        asa_total_supply := AssetParam.total(args.asset),
        Assert(asa_total_supply.hasValue()),
        # Global storage for TC-ASA and role ASA
        App.globalPut(Keys.asa, args.asset),
        # Opt-in
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.AssetTransfer),
        InnerTxnBuilder.SetField(TxnField.xfer_asset, args.asset),
        InnerTxnBuilder.SetField(TxnField.asset_amount, Int(0)),
        InnerTxnBuilder.SetField(TxnField.sender, current_app_address),
        InnerTxnBuilder.SetField(TxnField.asset_receiver, current_app_address),
        InnerTxnBuilder.Submit(),
        # Clawback reserve
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.AssetTransfer),
        InnerTxnBuilder.SetField(TxnField.xfer_asset, args.asset),
        InnerTxnBuilder.SetField(TxnField.asset_amount, asa_total_supply.value()),
        InnerTxnBuilder.SetField(TxnField.asset_sender, Txn.sender()),
        InnerTxnBuilder.SetField(TxnField.asset_receiver, current_app_address),
        InnerTxnBuilder.Submit(),
        Approve(),
    )


def on_create(cfg: Config) -> Expr:
    """Writes provided configuration to global state."""
    return Seq(
        *(  # NOTE: Here we are calling an API of `Config` that seems out of place here.
            # Refactor this to provide the mapping AVM key/value under a better API.
            App.globalPut(Bytes(Config.field_to_key(f)), cfg.encode_to_avm(f))
            for f in dataclasses.fields(cfg)
        ),
        Approve(),
    )


def on_call(_: Config) -> Expr:
    precondition = And(
        Txn.type_enum() == TxnType.ApplicationCall,  # Pedantic.
        Txn.application_args.length() >= Int(ABI.ON_CALL_NUM_APP_ARGS),
        Txn.rekey_to() == Global.zero_address(),  # Pedantic.
    )

    selector = Txn.application_args[ABI.ON_CALL_NUM_APP_ARGS - 1]
    return Seq(
        Assert(precondition),
        # Poor man dispatcher based on ABI selectors.
        Cond(*([selector == Bytes(k), f()] for k, f in ABI.DISPATCH_TABLE.items())),
    )


def on_optin(_: Config) -> Expr:
    return Seq(Approve())


def on_update(_: Config) -> Expr:
    precondition = is_master(Txn.sender())
    return Seq(Assert(precondition), Approve())


def on_delete(_: Config) -> Expr:
    return Seq(Reject())


def on_closeout_or_clear(_: Config) -> Expr:
    return Seq(Approve())


def asc_approval(cfg: Config) -> Expr:
    return Cond(
        [Txn.application_id() == Int(0), on_create(cfg)],
        [Txn.on_completion() == OnComplete.NoOp, on_call(cfg)],
        [Txn.on_completion() == OnComplete.OptIn, on_optin(cfg)],
        [Txn.on_completion() == OnComplete.CloseOut, on_closeout_or_clear(cfg)],
        [Txn.on_completion() == OnComplete.UpdateApplication, on_update(cfg)],
        [Txn.on_completion() == OnComplete.DeleteApplication, on_delete(cfg)],
        # ClearStateProgram will execute on ClearState, no need to worry about it here.
    )


def compile_stateful(program) -> str:
    return compileTeal(
        program, Mode.Application, assembleConstants=True, version=TEAL_VERSION
    )


if __name__ == "__main__":
    # Allow quickly testing compilation.
    from test_tc_asa import test_compile

    test_compile()
