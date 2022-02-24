# Transfer-controlled Algorand Standard Asset (TC-ASA)

Reference implementation for a Transfer-controlled Algorand Standard Asset
(TC-ASA), which extends an ASA to provide custom or more granular control around
`transfer`, `mint` and `burn` operations. Think of it like Algorand's ERC-20.

It implements the following:

- Setting a "global freeze" flag, that prevents all token transfers.
- Individually whitelisting/locking users.

Can be extended to implement any form of control over the transfer of the token,
e.g.:

- Requiring the payment of royalties when transferring the token.
- Restricting the minimum or maximum balance per user, the overall number of
  token holders, etc.
- Implementing vesting or minimum lock periods.

## Design

The TC-ASA ties together:

- An Algorand Standard Asset (ASA), created with the `defaultFrozen` flag set to
  prevents all `xfer` operations.
- An Algorand Smart Contract (ASC), which holds the `clawback`, `freeze`,
  `manager` and `reserve` roles over the ASA.

All operations on the ASA require an application call to the ASC. For instance,
a call to the ABI method `transfer(account,uint64,asset)` will transfer `uint64`
units of the `asset` (the ASA) from the transaction `Sender` to `account` (the
recipient). Under the hood, the ASC creates an inner clawback transaction
(`itxn`) that moves the ASA.

## ABI methods and calls

The `transfer` method provides the fundamental building block for all other
operations. For instance, if implementing royalties you would extend `transfer`
so that it also checks for an additional payment to the royalty owner (e.g.
through a group transfer):

- `transfer(account,uint64,asset)`: Transfer `uint64` units of `asset` (must be
  a reference to the TC-ASA) from `Sender` to `account`.

### `master` only

The following methods can only be invoked by the `master` account, which defaults
to the ASC `creator`:

- `init(asset)`: Initializes the TC-ASA by clawing back the total ASA supply
  into the account managed by this ASC (the `Reserve`). Can only be called once.
- `mint(account,uint64,asset)`: Mints `uint64` units of `asset` from `Reserve`
  to `account`.
- `burn(account,uint64,asset)`: Burns `uint64` units of `asset` from `account`
  to `Reserve`.
- `setWhitelist(account,bool)`: Sets the `whitelisted` flag of `account`.
  `whitelisted` must be `true` to receive funds.
- `setLock(account,bool)`: Sets the `locked` flag of `account`. `locked` must be
  `false` to `transfer` funds.
- `setFreeze(bool)`: Sets the global `frozen` flag. `frozen` must be `false` to
  issue `mint` or `transfer` operations.

### ASC life cycle

- `master` only can update the ASC.
- Anyone can `opt-in` to the ASC.
- `closeout`, `clear` and `delete` have not been implemented.
  - WARNING: Clearing the application state for a user with outstanding funds
    will prevent them from calling `transfer`.

## Usage

- The file `tc_asa.py` provides the PyTeal implementation and, if executed,
  writes the TEAL contract to `/tmp/tc_asa.teal`.
- The file `deploy.py` provides helpers to deploy the ASA and the ASC to the
  network.
  - By default, it will run against an Algorand
    [sandbox](https://github.com/algorand/sandbox) endpoints.
  - Will print the JSON ABI specification to `/tmp/contract.json`.

WARNING: This implementation has not been security-audited.

## Authors

- Adriano Di Luzio (@aldur)
- Cosimo Bassi (@cusma)
