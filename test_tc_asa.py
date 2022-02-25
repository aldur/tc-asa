#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TC-ASA tests."""

import dataclasses

from algosdk.error import AlgodHTTPError
import pytest

from tc_asa import (
    ABI,
    AVMState,
    Config,
    Keys,
    asc_approval,
    burn,
    compile_stateful,
    set_freeze_unfreeze_token,
    init,
    set_lock_unlock,
    mint,
    transfer,
    set_whitelist,
)

from deploy import (
    Account,
    abi_call,
    app_idx_to_account,
    create_and_fund,
    create_application,
    create_tc_asa,
    find_sandbox_faucet,
    fund,
    get_account_asa_balance,
    get_account_balance,
    get_application_state,
    get_asset_info,
    get_local_state,
    optin_to_application,
    optin_to_asset,
)


dummy_config = Config(
    master="XFYAYSEGQIY2J3DCGGXCPXY5FGHSVKM3V4WCNYCLKDLHB7RYDBU233QB5M",  # type: ignore
)


def copy_update_config(cfg: Config, **kwargs):
    c = dataclasses.asdict(cfg)
    for k, v in kwargs.items():
        if k not in c:
            raise KeyError(f"Trying to set invalid Config attribute '{k}'.")
        c[k] = v
    return Config(**c)  # This ensures that __post_init__ gets called.


def test_copy_update_config():
    c1 = dummy_config
    c2 = copy_update_config(c1, master="M")
    assert id(c1) != id(c2)
    assert c1.master != c2.master
    assert c2.master == "M"


def test_avm_state():
    @dataclasses.dataclass
    class C(AVMState):
        f: int
        g: bytes
        h: str

    assert C.n_uints() == 1
    assert C.n_bytes() == 2


def test_config():
    dataclasses.asdict(Keys)


def test_compile(path="/tmp/contract.teal"):
    # This test simply ensures we can compile the ASC
    with open(path, "w") as f:
        f.write(compile_stateful(asc_approval(dummy_config)))


def test_abi_interface():
    iface = {
        "name": "foo",
        "desc": "test interface",
        "args": [
            {"name": "bar", "type": "account", "desc": "user to lock/unlock."},
            {"name": "biz", "type": "bool"},
            {"name": "bux", "type": "asset"},
        ],
        "returns": {"type": "bool", "desc": "r"},
    }
    interface = ABI.Interface.parse(iface)
    assert interface.name == iface["name"]
    assert len(interface.args) == len(iface["args"])
    # assert "lock/unlock" in interface.args[1].desc  # desc has not been implemented yet
    assert interface.returns and interface.returns.type == "bool"
    assert interface.num_accounts == 1
    assert interface.num_app_args == 4  # includes selector.
    assert interface.num_assets == 1
    assert interface.returns.desc

    selector = ABI.abi_interface_to_signature(interface)
    assert selector == "foo(account,bool,asset)bool"

    del iface["returns"]
    with pytest.raises(KeyError):
        interface = ABI.Interface.parse(iface)

    assert interface.args.bar
    with pytest.raises(KeyError):
        interface.args.not_existing

    assert interface.args.bar.desc
    assert interface.desc


# https://docs.pytest.org/en/6.2.x/fixture.html#fixture-scopes
@pytest.fixture(scope="session")
def faucet() -> Account:
    faucet = find_sandbox_faucet()
    print(f" --- ⛲ Sandbox faucet account: {faucet.address}.")
    return faucet


@pytest.fixture()
def master(faucet) -> Account:
    master = create_and_fund(faucet)
    print(f" --- 💼 Created master account: {master.address}.")
    return master


@pytest.fixture()
def config(request):
    try:
        return request.param
    except AttributeError:
        return copy_update_config(dummy_config)


def _initialize_reserves(master, asc_idx, asa_idx):
    previous_balance = get_account_asa_balance(master, asa_idx)

    abi_call(master, init, asa_idx)
    with pytest.raises(AlgodHTTPError):
        # Can't initialize twice.
        abi_call(master, init, asa_idx)

    current_balance = get_account_asa_balance(master, asa_idx)
    assert current_balance == 0
    assert (
        get_account_asa_balance(app_idx_to_account(asc_idx), asa_idx)
        == previous_balance
    )


@pytest.fixture()
def asa_asc_indexes(config, master, faucet) -> tuple[int, int]:
    config.master = master.address  # type: ignore
    asc_idx = create_application(master, config)

    for m in ABI.DISPATCH_TABLE.values():
        m.asc_id = asc_idx

    app_account = app_idx_to_account(asc_idx)
    fund(faucet, app_account)
    print(
        f" --- 🔧 Created and funded ASC: {asc_idx} with address {app_account.address}."
    )

    asa_idx = create_tc_asa(master, asc_idx)
    assert get_asset_info(asa_idx)["default-frozen"]
    asset_info = get_asset_info(asa_idx)
    for k in ["clawback", "freeze", "manager", "reserve"]:
        assert asset_info[k] == app_account.address
    print(f" --- 🥇 Created TC-ASA: {asa_idx}.")

    _initialize_reserves(master, asc_idx, asa_idx)
    print(" --- 🥇 Tied together TC-ASA and the ASC.")

    return asa_idx, asc_idx


@pytest.fixture()
def asa_idx(asa_asc_indexes: tuple[int, int]) -> int:
    asa, asc = asa_asc_indexes
    del asc
    return asa


@pytest.fixture()
def asc_idx(asa_asc_indexes: tuple[int, int]) -> int:
    asa, asc = asa_asc_indexes
    del asa
    return asc


@pytest.fixture()
def asc_idx_address(asc_idx) -> Account:
    return app_idx_to_account(asc_idx)


def test_asc_creation(master: Account, asc_idx: int):
    state = get_application_state(asc_idx)
    assert master.decoded_address == state["master"]


# We do not scope this to `session` to get a fresh user for each test.
@pytest.fixture()
def opted_in_user(opted_in_user_factory):
    return opted_in_user_factory()


@pytest.fixture()
def opted_in_user_factory(asc_idx, asa_idx, faucet):
    def _factory():
        user = create_and_fund(faucet)
        print(f" --- 👨  Created user account: {user.address}.")
        optin_to_application(user, asc_idx)
        print(" --- 👨  user opts into the application.")
        optin_to_asset(user, asa_idx)
        print(" --- 👨  user opts into the ASA.")
        return user

    return _factory


def test_double_optin(asc_idx, opted_in_user):
    with pytest.raises(AlgodHTTPError):
        # This fails with 'has already opted in to app'
        optin_to_application(opted_in_user, asc_idx)


@pytest.fixture()
def opted_out_user(faucet):
    user = create_and_fund(faucet)
    print(f" --- 👨  Created opted-out user account: {user.address}.")
    return user


@pytest.fixture
def minimum_mint_quantity() -> int:
    return int(5 * 10**6)


class TestLockUnlock:
    def test_lock_unlock(self, master, opted_in_user):
        abi_call(master, set_lock_unlock, opted_in_user, True)
        with pytest.raises(AlgodHTTPError):
            # Can't do it twice
            abi_call(master, set_lock_unlock, opted_in_user, True)

    def test_lock_unlock_no_permissions(self, opted_in_user, whitelisted_user_factory):
        for user in [opted_in_user, whitelisted_user_factory()]:
            with pytest.raises(AlgodHTTPError):
                # No permissions to unlock
                abi_call(
                    user,
                    set_lock_unlock,
                    opted_in_user,
                    False,
                )

    def test_lock_unlock_no_optin(self, master, opted_out_user):
        with pytest.raises(AlgodHTTPError):
            # Can't lock someone who hasn't performed opt-in
            abi_call(master, set_lock_unlock, opted_out_user, False)


class TestFreezeUnfreeze:
    def test_freeze_unfreeze(self, master, asc_idx):
        _ = asc_idx
        for flag in [True, False]:
            abi_call(master, set_freeze_unfreeze_token, flag)
            with pytest.raises(AlgodHTTPError):
                # Can't do it twice
                abi_call(master, set_freeze_unfreeze_token, flag)

    def test_freeze_unfreeze_no_permissions(
        self, opted_in_user, opted_out_user, asc_idx
    ):
        _ = asc_idx
        for user in [opted_in_user, opted_out_user]:
            with pytest.raises(AlgodHTTPError):
                # Only the master can freeze/unfreeze.
                abi_call(user, set_freeze_unfreeze_token, False)

    def test_freeze_unfreeze_bad_flag(self, opted_in_user, asc_idx):
        _ = asc_idx
        with pytest.raises(AssertionError):
            # Invalid flag
            abi_call(
                opted_in_user,
                set_freeze_unfreeze_token,
                "SOME_RANDOM_STRING",
            )


class TestWhitelist:
    def test_whitelist_no_permissions(self, opted_in_user):
        with pytest.raises(AlgodHTTPError):
            abi_call(
                opted_in_user,  # No permissions
                set_whitelist,
                opted_in_user,
                True,
            )

    def test_whitelist(self, master, opted_in_user, asc_idx):
        abi_call(
            master,
            set_whitelist,
            opted_in_user,
            True,
        )
        local_state = get_local_state(opted_in_user, asc_idx)
        assert local_state["is_whitelisted"] == 0x80

        abi_call(
            master,
            set_whitelist,
            opted_in_user,
            False,
        )
        local_state = get_local_state(opted_in_user, asc_idx)
        assert local_state["is_whitelisted"] == 0

    def test_whitelist_twice(self, master, whitelisted_user):
        with pytest.raises(AlgodHTTPError):
            # Already whitelisted
            abi_call(
                master,
                set_whitelist,
                whitelisted_user,
                True,
            )


@pytest.fixture()
def whitelisted_user_factory(
    master,
    opted_in_user_factory,
):
    def _factory():
        user = opted_in_user_factory()
        abi_call(
            master,
            set_whitelist,
            user,
            True,
        )
        return user

    return _factory


@pytest.fixture()
def whitelisted_user(whitelisted_user_factory):
    return whitelisted_user_factory()


@pytest.fixture()
def funded_user_factory(
    minimum_mint_quantity,
    whitelisted_user_factory,
    mint_call,
):
    def _factory(quantity=None):
        user = whitelisted_user_factory()
        quantity = quantity or minimum_mint_quantity * 2
        mint_call(
            user,
            quantity,
        )
        return user

    return _factory


@pytest.fixture()
def funded_user(funded_user_factory):
    return funded_user_factory()


@pytest.fixture()
def mint_call(master, asa_idx):
    def _partial(target, amount, sender=None):
        return abi_call(
            sender or master,
            mint,
            target,
            amount,
            asa_idx,
        )

    return _partial


class TestMint:
    def test_mint(
        self,
        whitelisted_user,
        asa_idx,
        mint_call,
        asc_idx_address,
        minimum_mint_quantity,
    ):
        amount = minimum_mint_quantity

        previous_user_balance = get_account_asa_balance(whitelisted_user, asa_idx)
        previous_treasury_balance = get_account_asa_balance(asc_idx_address, asa_idx)

        mint_call(
            whitelisted_user,
            amount,
        )

        current_balance = get_account_asa_balance(whitelisted_user, asa_idx)
        current_treasury_balance = get_account_asa_balance(asc_idx_address, asa_idx)
        assert current_balance == previous_user_balance + amount
        assert current_treasury_balance == previous_treasury_balance - amount

        mint_call(
            whitelisted_user,
            amount,
        )

    def test_mint_no_privileges(
        self,
        whitelisted_user,
        opted_in_user,
        mint_call,
        minimum_mint_quantity,
    ):
        with pytest.raises(AlgodHTTPError):
            # Need to be privileged.
            mint_call(whitelisted_user, minimum_mint_quantity, sender=opted_in_user)

    def test_mint_no_whitelist(
        self,
        opted_in_user,
        mint_call,
    ):
        with pytest.raises(AlgodHTTPError):
            mint_call(opted_in_user, 2)

    def test_mint_zero_amount(
        self,
        whitelisted_user,
        mint_call,
    ):
        with pytest.raises(AlgodHTTPError):
            mint_call(whitelisted_user, 0)

    def test_mint_while_locked(
        self, master, whitelisted_user, minimum_mint_quantity, mint_call
    ):
        abi_call(master, set_lock_unlock, whitelisted_user, True)
        mint_call(
            whitelisted_user,
            minimum_mint_quantity,
        )  # This is allowed.

    def test_mint_while_frozen(
        self,
        master,
        whitelisted_user,
        minimum_mint_quantity,
        mint_call,
    ):
        abi_call(master, set_freeze_unfreeze_token, True)
        with pytest.raises(AlgodHTTPError):
            mint_call(
                whitelisted_user,
                minimum_mint_quantity,
            )  # Not allowed.
        abi_call(master, set_freeze_unfreeze_token, False)


class TestTransfer:
    def test_transfer_to_new_user(
        self,
        asa_idx,
        funded_user,
        whitelisted_user,
        minimum_mint_quantity,
        transfer_call,
        asc_idx_address,
    ):
        sender = funded_user
        receiver = whitelisted_user

        previous_sender_balance = get_account_asa_balance(sender, asa_idx)
        previous_receiver_balance = get_account_asa_balance(receiver, asa_idx)
        previous_treasury_balance = get_account_asa_balance(asc_idx_address, asa_idx)
        amount = minimum_mint_quantity

        assert minimum_mint_quantity < previous_sender_balance
        transfer_call(
            sender,
            receiver,
            amount,
        )
        assert previous_sender_balance - amount == get_account_asa_balance(
            sender, asa_idx
        )
        assert previous_receiver_balance + amount == get_account_asa_balance(
            receiver, asa_idx
        )
        assert (
            get_account_asa_balance(asc_idx_address, asa_idx)
            == previous_treasury_balance
        )

    def test_transfer_to_existing_user(
        self,
        asa_idx,
        funded_user,
        whitelisted_user,
        transfer_call,
        asc_idx_address,
    ):
        sender = funded_user
        receiver = whitelisted_user

        previous_sender_balance = get_account_asa_balance(sender, asa_idx)
        previous_receiver_balance = get_account_asa_balance(receiver, asa_idx)
        previous_treasury_balance = get_account_asa_balance(asc_idx_address, asa_idx)
        amount = previous_sender_balance
        transfer_call(
            sender,
            receiver,
            previous_sender_balance,
        )
        assert previous_sender_balance - amount == get_account_asa_balance(
            sender, asa_idx
        )
        assert previous_receiver_balance + amount == get_account_asa_balance(
            receiver, asa_idx
        )
        assert (
            get_account_asa_balance(asc_idx_address, asa_idx)
            == previous_treasury_balance
        )

    def test_transfer_over_balance(
        self,
        asa_idx,
        funded_user,
        whitelisted_user,
        transfer_call,
    ):
        sender = funded_user
        receiver = whitelisted_user

        sender_balance = get_account_asa_balance(sender, asa_idx)
        amount = sender_balance + 1
        with pytest.raises(AlgodHTTPError):
            transfer_call(
                sender,
                receiver,
                amount,
            )

    def test_transfer_no_whitelist(
        self,
        asa_idx,
        funded_user,
        opted_in_user,
        transfer_call,
    ):
        sender = funded_user
        receiver = opted_in_user

        sender_balance = get_account_asa_balance(sender, asa_idx)
        amount = sender_balance
        with pytest.raises(AlgodHTTPError):
            transfer_call(
                sender,
                receiver,
                amount,
            )

    def test_transfer_no_amount(
        self,
        funded_user,
        whitelisted_user,
        transfer_call,
    ):
        sender = funded_user
        receiver = whitelisted_user

        amount = 0
        with pytest.raises(AlgodHTTPError):
            transfer_call(
                sender,
                receiver,
                amount,
            )

    def test_transfer_while_locked(
        self,
        master,
        funded_user,
        whitelisted_user,
        minimum_mint_quantity,
        transfer_call,
    ):
        sender = funded_user
        receiver = whitelisted_user

        # Lock sender.
        abi_call(master, set_lock_unlock, sender, True)

        with pytest.raises(AlgodHTTPError):
            transfer_call(
                sender,
                receiver,
                minimum_mint_quantity,
            )

        # Unlock the sender and lock the receiver
        abi_call(master, set_lock_unlock, sender, False)
        abi_call(master, set_lock_unlock, receiver, True)
        transfer_call(
            sender,
            receiver,
            minimum_mint_quantity,
        )
        with pytest.raises(AlgodHTTPError):
            # Check that the vice-versa does not work.
            transfer_call(
                receiver,
                sender,
                minimum_mint_quantity,
            )

    def test_transfer_while_frozen(
        self,
        master,
        funded_user,
        whitelisted_user,
        minimum_mint_quantity,
        transfer_call,
    ):
        abi_call(master, set_freeze_unfreeze_token, True)

        sender = funded_user
        receiver = whitelisted_user

        with pytest.raises(AlgodHTTPError):
            transfer_call(
                sender,
                receiver,
                minimum_mint_quantity,
            )

    def test_trasfer_to_self(
        self,
        funded_user,
        minimum_mint_quantity,
        transfer_call,
    ):
        with pytest.raises(AlgodHTTPError):
            # No self payments
            transfer_call(
                funded_user,
                funded_user,
                minimum_mint_quantity,
            )


@pytest.fixture()
def transfer_call(asa_idx):
    def _partial(source, target, amount):
        return abi_call(
            source,
            transfer,
            target,
            amount,
            asa_idx,
        )

    return _partial


@pytest.fixture()
def burn_call(master, asa_idx):
    def _partial(target, amount, sender=None):
        return abi_call(
            sender or master,
            burn,
            target,
            amount,
            asa_idx,
        )

    return _partial


class TestBurn:
    def test_burn(
        self,
        asa_idx,
        funded_user,
        burn_call,
        asc_idx_address,
        minimum_mint_quantity,
    ):
        previous_balance = get_account_balance(funded_user).get(asa_idx, 0)
        previous_treasury_balance = get_account_asa_balance(asc_idx_address, asa_idx)

        amount = minimum_mint_quantity
        burn_call(funded_user, amount)

        current_balance = get_account_asa_balance(funded_user, asa_idx)
        current_treasury_balance = get_account_asa_balance(asc_idx_address, asa_idx)
        assert current_balance == previous_balance - amount
        assert current_treasury_balance == previous_treasury_balance + amount

        previous_balance = current_balance
        previous_treasury_balance = current_treasury_balance


def test_fixtures(
    faucet,
    master,
    asc_idx,
    opted_in_user,
    opted_out_user,
    whitelisted_user,
    funded_user,
):
    assert faucet.address
    assert master.address

    assert isinstance(asc_idx, int)
    assert opted_in_user.address
    assert opted_out_user.address
    assert whitelisted_user.address
    assert funded_user.address
