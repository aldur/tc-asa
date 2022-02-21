#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import base64
import dataclasses
import json
import time
from typing import Any, Optional, Union, cast

import algosdk
from algosdk import encoding, mnemonic, util
from algosdk.abi import StringType
from algosdk.future import transaction
from algosdk.kmd import KMDClient
from algosdk.v2client import algod, indexer
from algosdk.wallet import Wallet

from state import AVMState
from tc_asa import (
    ABI,
    Config,
    LocalConfig,
    asc_approval,
    compile_stateful,
    initialize_reserves,
    on_closeout_or_clear,
)

ALGOD_ADDRESS = "http://localhost:4001"
ALGOD_TOKEN = "a" * 64
KMD_ADDRESS = "http://localhost:4002"
KMD_TOKEN = ALGOD_TOKEN
INDEXER_ADDRESS = "http://localhost:8980"
INDEXER_TOKEN = ALGOD_TOKEN

ASSET_UNIT_NAME = "TC-ASA"
ASSET_NAME = "TCASA"
ASSET_TOTAL = int(2 ** 64 - 1)
ASSET_DECIMALS = 6
FUND_ACCOUNT_ALGOS = util.algos_to_microalgos(100)  # Algos

FLAT_FEE = 1000

algod_client = algod.AlgodClient(algod_token=ALGOD_TOKEN, algod_address=ALGOD_ADDRESS)
kmd_client = KMDClient(kmd_token=KMD_TOKEN, kmd_address=KMD_ADDRESS)
indexer_client = indexer.IndexerClient(
    indexer_token=INDEXER_TOKEN, indexer_address=INDEXER_ADDRESS
)


@dataclasses.dataclass
class Account:
    address: str
    private_key: Optional[
        str
    ]  # Must be explicitly set to None when setting `lsig` or `app`.
    lsig: Optional[transaction.LogicSig] = None
    app: Optional[int] = None

    def __post_init__(self):
        assert self.private_key or self.lsig or self.app

    def mnemonic(self) -> str:
        return mnemonic.from_private_key(self.private_key)

    def is_lsig(self) -> bool:
        return bool(not self.private_key and self.lsig)

    @classmethod
    def create_account(cls) -> "Account":
        private_key, address = algosdk.account.generate_account()
        return cls(private_key=private_key, address=cast(str, address))

    @property
    def decoded_address(self):
        return encoding.decode_address(self.address)


def get_params(client):
    params = client.suggested_params()
    params.flat_fee = True
    params.fee = FLAT_FEE

    return params


def wait_for_confirmation(client, txid: str):
    """
    Wait until the transaction is confirmed before proceeding.
    """
    last_round = client.status().get("last-round")
    txinfo = client.pending_transaction_info(txid)

    while not txinfo.get("confirmed-round", -1) > 0:
        print(f"Waiting for transaction {txid} confirmation.")
        last_round += 1
        client.status_after_block(last_round)
        txinfo = client.pending_transaction_info(txid)

    print(f"Transaction {txid} confirmed in round {txinfo.get('confirmed-round')}.")
    return txinfo


def sign(account: Account, txn):
    if account.is_lsig():
        return transaction.LogicSigTransaction(txn, account.lsig)  # type: ignore

    assert account.private_key
    return txn.sign(account.private_key)


def sign_send_wait(account: Account, txn):
    """Sign a transaction, submit it, and wait for its confirmation."""
    signed_txn = sign(account, txn)
    tx_id = signed_txn.transaction.get_txid()
    transaction.write_to_file([signed_txn], "/tmp/txn.signed", overwrite=True)
    algod_client.send_transactions([signed_txn])
    wait_for_confirmation(algod_client, tx_id)

    return algod_client.pending_transaction_info(tx_id)


def create_asset(creator_account: Account, **kwargs) -> int:
    """Create an asset and return its ID."""
    params = get_params(algod_client)

    config_kwargs = {
        "sender": creator_account.address,
        "sp": params,
        "total": ASSET_TOTAL,
        "default_frozen": True,
        "unit_name": ASSET_UNIT_NAME,
        "asset_name": ASSET_NAME,
        "manager": creator_account.address,
        "reserve": creator_account.address,
        "freeze": creator_account.address,
        "clawback": creator_account.address,
        "decimals": ASSET_DECIMALS,
    }

    config_kwargs.update(**kwargs)
    txn = transaction.AssetConfigTxn(**config_kwargs)

    ptx = sign_send_wait(creator_account, txn)
    return ptx["asset-index"]


def create_tc_asa(creator_account: Account, tc_asc_idx: int) -> int:
    tc_asc_address = app_idx_to_account(tc_asc_idx).address
    kwargs = {
        "manager": tc_asc_address,
        "reserve": tc_asc_address,
        "freeze": tc_asc_address,
        "clawback": tc_asc_address,
        # TODO: Making up my own standard here :) standardize this.
        "url": f"https://algorand.com/tc-asa/{tc_asc_idx}",
        "unit_name": ASSET_UNIT_NAME,
        "asset_name": ASSET_NAME,
        "decimals": ASSET_DECIMALS,
    }
    return create_asset(creator_account, **kwargs)


def optin_to_asset(account: Account, asset_id: int):
    params = get_params(algod_client)
    txn = transaction.AssetTransferTxn(
        sender=account.address,
        sp=params,
        receiver=account.address,
        amt=0,
        index=asset_id,
    )
    return sign_send_wait(account, txn)


def compile_program(source_code):
    compile_response = algod_client.compile(source_code)
    return base64.b64decode(compile_response["result"])


def optin_to_application(account: Account, app_id: int):
    params = get_params(algod_client)
    txn = transaction.ApplicationOptInTxn(account.address, params, app_id)
    return sign_send_wait(account, txn)


def close_out_application(account, app_id):
    params = get_params(algod_client)
    txn = transaction.ApplicationCloseOutTxn(account.address, params, app_id)
    return sign_send_wait(account, txn)


def find_sandbox_faucet() -> Account:
    default_wallet_name = kmd_client.list_wallets()[0]["name"]
    wallet = Wallet(
        default_wallet_name, "", kmd_client
    )  # Sandbox's wallet has no password

    for account_ in wallet.list_keys():
        info = algod_client.account_info(account_)
        if (
            info
            and info.get("status") == "Online"
            # and info.get("created-at-round", 0) == 0  # Needs the indexer.
        ):
            return Account(address=account_, private_key=wallet.export_key(account_))

    raise KeyError("Could not find sandbox faucet")


def create_and_fund(faucet: Account) -> Account:
    new_account = Account.create_account()
    print(f"Funding new account: {new_account.address}.")

    fund(faucet, new_account)

    return new_account


def fund(faucet: Account, receiver: Account, amount=FUND_ACCOUNT_ALGOS):
    params = get_params(algod_client)
    txn = transaction.PaymentTxn(faucet.address, params, receiver.address, amount)
    return sign_send_wait(faucet, txn)


def group_sign_send(signers, txns):
    assert len(signers) == len(txns)
    signed_group = []
    gid = transaction.calculate_group_id(txns)

    for signer, t in zip(signers, txns):
        t.group = gid
        signed_group.append(sign(signer, t))

    transaction.write_to_file(signed_group, "/tmp/txn.signed", overwrite=True)

    gtxn_id = algod_client.send_transactions(signed_group)
    return wait_for_confirmation(algod_client, gtxn_id)


def app_idx_to_account(app_idx: int) -> Account:
    return Account(
        cast(
            str,
            encoding.encode_address(
                encoding.checksum(b"appID" + (app_idx).to_bytes(8, "big"))
            ),
        ),
        private_key=None,
        app=app_idx,
    )


def create_application(master: Account, cfg: Config) -> int:
    """Deploy an ASC1 and return its index."""
    global_schema = transaction.StateSchema(Config.n_uints(), Config.n_bytes())
    local_schema = transaction.StateSchema(LocalConfig.n_uints(), LocalConfig.n_bytes())

    approval_program = compile_program(compile_stateful(asc_approval(cfg)))
    clear_program = compile_program(compile_stateful(on_closeout_or_clear(cfg)))

    on_complete = transaction.OnComplete.NoOpOC.real
    params = get_params(algod_client)

    txn = transaction.ApplicationCreateTxn(
        master.address,
        params,
        on_complete,
        approval_program,
        clear_program,
        global_schema,
        local_schema,
        extra_pages=(len(approval_program) + len(clear_program)) // 2048,
    )

    transaction_response = sign_send_wait(master, txn)
    return transaction_response["application-index"]


def decode_state(state):
    return {
        # We are assuming that global space `key` are printable.
        # If that's not necessarily true, we can change that.
        base64.b64decode(s["key"]).decode(): base64.b64decode(s["value"]["bytes"])
        if s["value"]["type"] == 1
        else int(s["value"]["uint"])
        for s in state
    }


def get_application_state(asc_idx: int) -> dict[str, Union[bytes, int]]:
    global_state = algod_client.application_info(asc_idx)["params"]["global-state"]
    global_state = decode_state(global_state)
    return global_state


def get_local_state(account: Account, asc_idx: int) -> dict[str, Union[bytes, int]]:
    local_states = algod_client.account_info(account.address)["apps-local-state"]
    local_state = [s for s in local_states if s["id"] == asc_idx][0].get(
        "key-value", {}
    )
    local_state = decode_state(local_state)
    return local_state


def get_account_balance(account: Account) -> dict[int, int]:
    account_info = algod_client.account_info(account.address)
    balances = {a["asset-id"]: int(a["amount"]) for a in account_info["assets"]}
    balances[0] = int(account_info["amount"])
    return balances


def get_account_asa_balance(account: Account, asa_idx: int) -> int:
    return get_account_balance(account).get(asa_idx, 0)


def get_asset_info(asa_idx) -> dict:
    return algod_client.asset_info(asa_idx)["params"]


def abi_call(
    sender: Account,
    method,
    *args,
) -> Any:  # TODO: Correctly specify the return type here.
    """
    ABI call from `sender` to `method`, with `*args`

    Specify `n_app_calls` to add no-ops that will increase the AppCall budget.

    `group_senders_txns` allows tailing other transactions to the ABI call in a
    group; expects an iterable of pairs (sender, transaction).
    """
    interface = method.interface
    params = get_params(algod_client)

    foreign_accounts = []
    foreign_assets = []
    app_args = [method.selector]

    # TODO: Encoding might re-use foreign elements (accounts) more than once.
    # This can be made more efficient.

    assert len(interface.args) == len(args)
    for i, iarg in enumerate(interface.args):
        # Here we encode the arguments for the ABI.
        # TODO: For now, we don't encode int to bytes.
        if iarg.type == "account":
            app_args.append(len(foreign_accounts) + 1)
            foreign_accounts.append(args[i].address)
        elif iarg.type == "asset":
            app_args.append(len(foreign_assets))
            foreign_assets.append(args[i])
        elif iarg.type == "bool":
            app_args.append(0x80 if args[i] else 0x00)
        elif iarg.type == "uint64":
            app_args.append(int(args[i]))
        elif iarg.type == "string":
            app_args.append(StringType().encode(args[i]))
        else:  # Default to byte encoding.
            app_args.append(args[i])

    txns = [
        transaction.ApplicationNoOpTxn(
            sender=sender.address,
            sp=params,
            index=method.asc_id,
            app_args=app_args,
            accounts=foreign_accounts,
            foreign_assets=foreign_assets,
        )
    ]  # type: ignore

    senders = [sender] * len(txns)

    tx_info = group_sign_send(senders, txns)
    if interface.returns.type == "void":
        return tx_info  # Useful for debugging.

    logs = tx_info.get("logs")
    assert logs, "Was supposed to log, but did not."
    returned_log = base64.b64decode(logs[0])

    assert returned_log[:4] == bytes.fromhex(
        "151f7c75"
    )  # Literally hash('return')[:4])
    returned_log = returned_log[4:]

    if interface.returns.type.startswith("uint"):
        return int.from_bytes(returned_log, "big")
    if interface.returns.type == "bool":
        return bool(int.from_bytes(returned_log, "big"))

    return returned_log  # Fallback to returning raw bytes.


def deploy():
    faucet = find_sandbox_faucet()
    print(f" --- ⛲  Sandbox faucet account: {faucet.address}.")

    master = create_and_fund(faucet)
    print(f" --- 💼  Created master account: {master.address}.")
    print(f" --- 💼  Master account mnemonic:\n{master.mnemonic()}")

    config = Config(master=AVMState.Address(master.address))
    asc_idx = create_application(master, config)

    for m in ABI.DISPATCH_TABLE.values():
        m.asc_id = asc_idx

    app_account = app_idx_to_account(asc_idx)
    fund(faucet, app_account)
    print(
        f" --- 🔧  Created and funded ASC: {asc_idx} with address {app_account.address}."
    )

    asa_idx = create_tc_asa(master, asc_idx)
    print(f" --- 🥇  Created TC-ASA: {asa_idx}.")

    abi_call(master, initialize_reserves, asa_idx)
    print(" --- 🥇  Tied together the ASA into the ASC for the TC-ASA.")

    user = create_and_fund(faucet)
    print(f" --- 👨  Created user account: {user.address}.")

    user = create_and_fund(faucet)
    optin_to_application(user, asc_idx)
    optin_to_asset(user, asa_idx)
    print(f" --- User {user.address} opted into the TC-ASA (application and asset).")

    contract_dict = ABI.to_contract_specification(
        algod_client.versions()["genesis_hash_b64"],
        asc_idx,
    )
    contract_path = "/tmp/contract.json"

    print(f" --- Saving contract definition to '{contract_path}'.")
    with open(contract_path, "w") as f:
        json.dump(contract_dict, f, indent=2)


if __name__ == "__main__":
    deploy()
