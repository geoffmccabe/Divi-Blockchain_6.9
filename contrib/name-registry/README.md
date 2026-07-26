# name-registry

The normative rules for **Divi Names**: one namespace covering human readable
addresses (HRAs) and DMT token tickers.

Plan and rationale: `docs/DIVI-NAMES-PLAN.md`.

## Why this crate exists separately

These rules must give byte-identical answers in the wallet, the explorer, the
indexer, and any third-party implementation. Two implementations that quietly
disagree about whether `D!VI` collides with `DIVI`, or about what a 6-character
name costs, produce two realities and proof-of-work cannot arbitrate between
them. So the rules live in one small crate with no I/O, no clock, and no
configuration, small enough to audit in one sitting.

It holds **no ledger state and makes no ownership decisions**. Those belong to an
indexer applying these rules to blocks in order.

## Modules

| module | what it owns |
|---|---|
| `charset` | length, character set, reserved-name normalisation |
| `fees` | length-tiered registration/renewal, term, grace, release auction |
| `commit` | commit-reveal maturity, `Hash160(salt ‖ name)` |
| `record` | DVXP type `0x05` encode/decode |

## For anyone building on this

Use `name_registry::quote()` as the single entry point for "is this name valid
and what does it cost". It returns the canonical uppercase form, and that string
is what gets committed. Splitting validation from canonicalisation at the call
site is how a user ends up registering something subtly different from what they
typed.

Use `name_registry::explain()` for the refusal text so that every Divi app says
the same thing about the same name.

## Relationship to `dmt-indexer`

`dmt-indexer/src/ticker.rs` used to own the charset and reserved-name logic. It
is now a thin re-export of `charset` with the ticker length bound applied, so DMT
behaviour is unchanged and there is exactly one copy of the rules.

## Honest limits

This is an overlay. The chain **carries and orders** these records; software
interprets them into a registry. The network does not validate name ownership,
and no opcode could make it. Accurate: *"permanently recorded and ordered by the
Divi chain."* Never: *"the network enforces this."*

A light client cannot verify a resolution itself; it is trusting whichever
indexer it asked. Resolution is higher stakes than a token balance: a wrong
balance is embarrassing, a wrong address resolution sends somebody's money to a
stranger. Any wallet built on this must show the resolved raw address before a
send.
