from __future__ import annotations

import asyncio
import json
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Dict, Iterable, List, Optional, Tuple, Union

import click
from blspy import AugSchemeMPL, G2Element
from chia.cmds.cmds_util import get_wallet_client
from chia.rpc.wallet_rpc_client import WalletRpcClient
from chia.types.blockchain_format.program import Program
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.spend_bundle import SpendBundle
from chia.util.bech32m import decode_puzzle_hash
from chia.util.byte_types import hexstr_to_bytes
from chia.util.config import load_config
from chia.util.default_root import DEFAULT_ROOT_PATH
from chia.util.ints import uint64
from chia.wallet.cat_wallet.cat_utils import (
    CAT_MOD,
    SpendableCAT,
    construct_cat_puzzle,
    unsigned_spend_bundle_for_spendable_cats,
)
from chia.wallet.util.tx_config import DEFAULT_TX_CONFIG
from chia.util.bech32m import decode_puzzle_hash
from chia.wallet.vc_wallet.cr_cat_drivers import ProofsChecker, construct_cr_layer
from chia.wallet.transaction_record import TransactionRecord
from clvm_tools.binutils import assemble
from clvm_tools.clvmc import compile_clvm_text

from chia.types.condition_opcodes import ConditionOpcode
from chia.wallet.lineage_proof import LineageProof
from chia.types.coin_spend import CoinSpend#, make_spend


# Loading the client requires the standard chia root directory configuration that all of the chia commands rely on
@asynccontextmanager
async def get_context_manager(
    wallet_rpc_port: Optional[int], fingerprint: int, root_path: Path
) -> AsyncIterator[Tuple[WalletRpcClient, int, Dict[str, Any]]]:
    config = load_config(root_path, "config.yaml")
    _wallet_rpc_port = (
        config["wallet"]["rpc_port"] if wallet_rpc_port is None else wallet_rpc_port
    )
    async with get_wallet_client(
        _wallet_rpc_port, root_path=root_path, fingerprint=fingerprint
    ) as args:
        yield args


async def get_signed_tx(
    wallet_rpc_port: Optional[int],
    fingerprint: int,
    wallet_id:int,
    ph: bytes32,
    amt: uint64,
    fee: uint64,
    root_path: Path,
) -> TransactionRecord:
    async with get_context_manager(
        wallet_rpc_port, fingerprint, root_path
    ) as client_etc:
        wallet_client, _, _ = client_etc
        if wallet_client is None:
            raise ValueError(
                "Error getting wallet client. Make sure wallet is running."
            )
        return await wallet_client.create_signed_transaction(
            [{"puzzle_hash": ph, "amount": amt}], DEFAULT_TX_CONFIG, wallet_id = wallet_id, fee=fee  # TODO: no default tx config
        )


async def push_tx(
    wallet_rpc_port: Optional[int],
    fingerprint: int,
    bundle: SpendBundle,
    root_path: Path,
) -> Any:
    async with get_context_manager(
        wallet_rpc_port, fingerprint, root_path
    ) as client_etc:
        wallet_client, _, _ = client_etc
        if wallet_client is None:
            raise ValueError(
                "Error getting wallet client. Make sure wallet is running."
            )
        return await wallet_client.push_tx(bundle)  # type: ignore[no-untyped-call]


# The clvm loaders in this library automatically search for includable files in the directory './include'
def append_include(search_paths: Iterable[str]) -> List[str]:
    if search_paths:
        search_list = list(search_paths)
        search_list.append("./include")
        return search_list
    else:
        return ["./include"]


def parse_program(program: Union[str, Program], include: Iterable[str] = []) -> Program:
    prog: Program
    if isinstance(program, Program):
        return program
    else:
        if "(" in program:  # If it's raw clvm
            prog = Program.to(assemble(program))  # type: ignore[no-untyped-call]
        elif "." not in program:  # If it's a byte string
            prog = Program.from_bytes(hexstr_to_bytes(program))
        else:  # If it's a file
            with open(program, "r") as file:
                filestring: str = file.read()
                if "(" in filestring:  # If it's not compiled
                    # TODO: This should probably be more robust
                    if re.compile(r"\(mod\s").search(filestring):  # If it's Chialisp
                        prog = Program.to(
                            compile_clvm_text(filestring, append_include(include))  # type: ignore[no-untyped-call]
                        )
                    else:  # If it's CLVM
                        prog = Program.to(assemble(filestring))  # type: ignore[no-untyped-call]
                else:  # If it's serialized CLVM
                    prog = Program.from_bytes(hexstr_to_bytes(filestring))
        return prog


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

async def find_CAT_wallet_id_async(
        tail:str,
        wallet_rpc_port: Optional[int],
        fingerprint: int,
        root_path: Path,
    ) -> int:
    tail = parse_program(tail)
    tail_hash = tail.get_tree_hash()
    w_id:int = 0 
    async with get_context_manager(
        wallet_rpc_port, fingerprint, root_path
    ) as client_etc:
        wallet_client, _, _ = client_etc
        if wallet_client is None:
            raise ValueError(
                "Error getting wallet client. Make sure wallet is running."
            )
        wallets_info = await wallet_client.get_wallets(
            6  # get only CAT wallets
        )
        for wallet_info in wallets_info:
            if wallet_info['data'][:64] == str(tail_hash):
                w_id = int(wallet_info['id'])
    if w_id == 0:
        raise ValueError("Failed to get the wallet ID")
    
    wallet_client.close()
    await wallet_client.await_closed()

    return w_id



@click.command()
@click.pass_context
@click.option(
    "-l",
    "--tail",
    required=True,
    help="The TAIL program to launch this CAT with",
)
@click.option(
    "-c",
    "--curry",
    multiple=True,
    help="An argument to curry into the TAIL",
)
@click.option(
    "-s",
    "--solution",
    required=True,
    default="()",
    show_default=True,
    help="The solution to the TAIL program",
)
@click.option(
    "-t",
    "--send-to",
    required=True,
    help="The address these CATs will appear at once they are issued",
)
@click.option(
    "-a",
    "--amount",
    required=True,
    type=int,
    help=(
        "The amount to issue in mojos (regular XCH will be used to fund this)"
        "If negative - the amount to melt"
        ),
)
@click.option(
    "-m",
    "--fee",
    required=True,
    default=0,
    show_default=True,
    help="The fees for the transaction, in mojos",
)
@click.option(
    "-d",
    "--authorized-provider",
    type=str,
    multiple=True,
    help=(
        "A trusted DID that can issue VCs that are allowed to trade the CAT. Specifying this option will make the CAT "
        "a CR (credential restricted) CAT."
    ),
)
@click.option(
    "-r",
    "--proofs-checker",
    type=str,
    default=None,
    show_default=False,
    help=(
        "The program that checks the proofs of a VC for a CR-CAT. "
        "Specifying this option requires a value for --authorized-providers."
    ),
)
@click.option(
    "-v",
    "--cr-flag",
    type=str,
    multiple=True,
    help=(
        "Specify a list of flags to check a VC for in order to authorize this CR-CAT. "
        "Specifying this option requires a value for --authorized-providers. "
        "Cannot be used if a custom --proofs-checker is specified."
    )
)
@click.option(
    "-f",
    "--fingerprint",
    type=int,
    help="The wallet fingerprint to use as funds",
)
@click.option(
    "-sig",
    "--signature",
    multiple=True,
    help="A signature to aggregate with the transaction",
)
@click.option(
    "-as",
    "--spend",
    multiple=True,
    help="An additional spend to aggregate with the transaction",
)
@click.option(
    "-b",
    "--as-bytes",
    is_flag=True,
    help="Output the spend bundle as a sequence of bytes instead of JSON",
)
@click.option(
    "-sc",
    "--select-coin",
    is_flag=True,
    help="Stop the process once a coin from the wallet has been selected and return the coin",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    help="Quiet mode will not ask to push transaction to the network",
)
@click.option(
    "-p",
    "--push",
    is_flag=True,
    help="Automatically push transaction to the network in quiet mode",
)
@click.option(
    "--root-path",
    default=DEFAULT_ROOT_PATH,
    help="The root folder where the config lies",
    type=click.Path(),
    show_default=True,
)
@click.option(
    "--wallet-rpc-port",
    default=None,
    help="The RPC port the wallet service is running on",
    type=int,
)
def cli(
    ctx: click.Context,
    tail: str,
    curry: Tuple[str, ...],
    solution: str,
    send_to: str,
    amount: int,
    fee: int,
    authorized_provider: Tuple[str],
    proofs_checker: Optional[str],
    cr_flag: Tuple[str],
    fingerprint: int,
    signature: Tuple[str, ...],
    spend: Tuple[str, ...],
    as_bytes: bool,
    select_coin: bool,
    quiet: bool,
    push: bool,
    root_path: str,
    wallet_rpc_port: Optional[int],
) -> None:
    ctx.ensure_object(dict)

    asyncio.run(
        cmd_func(
            tail,
            curry,
            solution,
            send_to,
            amount,
            fee,
            authorized_provider,
            proofs_checker,
            cr_flag,
            fingerprint,
            signature,
            spend,
            as_bytes,
            select_coin,
            quiet,
            push,
            root_path,
            wallet_rpc_port,
        )
    )


async def cmd_func(
    tail: str,
    curry: Tuple[str, ...],
    solution: str,
    send_to: str,
    amount: int,
    fee: int,
    authorized_provider: Tuple[str],
    proofs_checker: Optional[str],
    cr_flag: Tuple[str],
    fingerprint: int,
    signature: Tuple[str, ...],
    spend: Tuple[str, ...],
    as_bytes: bool,
    select_coin: bool,
    quiet: bool,
    push: bool,
    root_path: str,
    wallet_rpc_port: Optional[int],
) -> None:

    if amount < 0:
        print("Trying to melt")

        tail = parse_program(tail)
        tail_hash = tail.get_tree_hash()
        solution = parse_program(solution)
        
        CAT_wallet_id = await find_CAT_wallet_id_async(tail, wallet_rpc_port, fingerprint = fingerprint, root_path = root_path)

        burn_coin_inner_puzzle = Program.to((
            1,
            [[ConditionOpcode.CREATE_COIN, 0, -113, tail, solution]]
        ))
        burn_coin_inner_puzzle_hash = burn_coin_inner_puzzle.get_tree_hash()

        temporary_burn_coin_puzzle = construct_cat_puzzle(CAT_MOD, tail.get_tree_hash(), burn_coin_inner_puzzle)

        tbc_ph = temporary_burn_coin_puzzle.get_tree_hash()


        CAT_amount_to_melt = -amount

        signed_tx = await get_signed_tx(
            wallet_rpc_port,
            fingerprint,
            CAT_wallet_id,
            burn_coin_inner_puzzle_hash,#cat_ph,
            uint64(CAT_amount_to_melt),
            uint64(0),
            Path(DEFAULT_ROOT_PATH),#Path(root_path),
        )
        
        if signed_tx.spend_bundle is None:
            raise ValueError("Error creating signed transaction")
        CAT_coin_to_melt = list(
            filter(lambda c: c.puzzle_hash == tbc_ph, signed_tx.spend_bundle.additions())
        )[0]
        
        for coin_spend in signed_tx.spend_bundle.coin_spends:
            if coin_spend.coin.name() == CAT_coin_to_melt.parent_coin_info:
                
                parent_CATcoin = coin_spend.coin
                pz = coin_spend.puzzle_reveal
                CAT_puzzle = parse_program(bytes(pz).hex())                
                
                inner_pz = CAT_puzzle.rest().rest().first().rest().rest().first().rest().rest().first().rest().first().rest()
                inner_pz_hash = inner_pz.get_tree_hash()

                """
                test_pz = construct_cat_puzzle(CAT_MOD, tail.get_tree_hash(), inner_pz)
                print(test_pz.get_tree_hash())
                print(parent_CATcoin.puzzle_hash == test_pz.get_tree_hash())
                """
                parent_CATcoin_innerpuzzlehashb32 = inner_pz_hash
                
                
        spendable_CATtomelt = SpendableCAT(
            coin = CAT_coin_to_melt,
            limitations_program_hash = tail_hash, #ZEROS_TOKEN_PUZZLE.get_tree_hash(),
            inner_puzzle = burn_coin_inner_puzzle,
            inner_solution = Program.to([]),#EMPTY_PROGRAM,#
            lineage_proof = LineageProof(
                parent_CATcoin.parent_coin_info, parent_CATcoin_innerpuzzlehashb32, uint64(parent_CATcoin.amount)
            ),        
            extra_delta = -CAT_coin_to_melt.amount,
            limitations_solution = solution,#Program.to([]),#solution,
            limitations_program_reveal=tail,
        )
        CATtomelt_spend = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [spendable_CATtomelt])

        inner_address = decode_puzzle_hash(send_to)
        
        intercept_coin_inner_puzzle = Program.to((
            1,
            [[ConditionOpcode.CREATE_COIN, inner_address, CAT_amount_to_melt]]
        ))

        intercept_coin_inner_puzzle_hash = intercept_coin_inner_puzzle.get_tree_hash()

        signed_tx_fee = await get_signed_tx(
            wallet_rpc_port,
            fingerprint,
            1, #wallet_id
            intercept_coin_inner_puzzle_hash,#cat_ph,
            uint64(0), # amount
            uint64(fee), # fee
            Path(DEFAULT_ROOT_PATH),#Path(root_path),
        )

        if signed_tx.spend_bundle is None:
            raise ValueError("Error creating signed transaction")
        XCH_coin_sending_to_my_addr = list(
            filter(lambda c: c.puzzle_hash == intercept_coin_inner_puzzle_hash, signed_tx_fee.spend_bundle.additions())
        )[0]
        
        list_of_coinspends = [
                CoinSpend(XCH_coin_sending_to_my_addr, intercept_coin_inner_puzzle, Program.to([])),
           ]
        unsigned_spend_bundle = SpendBundle(list_of_coinspends, G2Element())

        #signature: Tuple[str, ...] = []
        #spend: Tuple[str, ...] = []

        aggregated_signature = G2Element()
        for sig in signature:
            aggregated_signature = AugSchemeMPL.aggregate(
                [aggregated_signature, G2Element.from_bytes(hexstr_to_bytes(sig))]
            )

        aggregated_spend = SpendBundle([], G2Element())
        for bundle in spend:
            aggregated_spend = SpendBundle.aggregate(
                [aggregated_spend, SpendBundle.from_bytes(hexstr_to_bytes(bundle))]
            )

        # Aggregate everything together
        final_bundle = SpendBundle.aggregate(
            [
                signed_tx.spend_bundle,
                CATtomelt_spend,
                unsigned_spend_bundle,
                signed_tx_fee.spend_bundle,
                aggregated_spend,
                SpendBundle([], aggregated_signature),
            ]
        )
        final_bundle_dump = json.dumps(
            final_bundle.to_json_dict(), sort_keys=True, indent=4
            )

        if as_bytes:
            final_bundle_dump = bytes(final_bundle).hex()
        else:
            final_bundle_dump = json.dumps(
                final_bundle.to_json_dict(), sort_keys=True, indent=4
            )

        confirmation = push

        if not quiet:
            confirmation = input(
                "The transaction has been created, would you like to push it to the network? (Y/N)"
            ) in ["y", "Y", "yes", "Yes"]
        if confirmation:
            response = await push_tx(
                wallet_rpc_port, fingerprint, final_bundle, Path(root_path)
            )
            if "error" in response:
                print(f"Error pushing transaction: {response['error']}")
                return
            print("Successfully pushed the transaction to the network")

        if not confirmation:
            print(f"Spend Bundle: {final_bundle_dump}")        
        
        #print("most likely melted")
        return
# ===================== end of melting block

    tail = parse_program(tail)
    curried_args = [assemble(arg) for arg in curry]  # type: ignore[no-untyped-call]
    solution = parse_program(solution)
    inner_address = decode_puzzle_hash(send_to)
    address = inner_address

    # Potentially wrap address in CR layer
    extra_conditions: List[Program] = []
    if len(authorized_provider) > 0:
        ap_bytes = [bytes32(decode_puzzle_hash(ap)) for ap in authorized_provider]
        proofs_checker: Program
        if proofs_checker is not None:
            if len(cr_flag) > 0:
                print("Cannot specify values for both --proofs-checker and --cr-flag")
                return
            proofs_checker = parse_program(proofs_checker)
        elif len(cr_flag) > 0:
            proofs_checker = ProofsChecker(list(cr_flag)).as_program()
        else:
            print("Must specify either --proofs-checker or --cr-flag if specifying --authorized-provider")
            return
        extra_conditions.append(Program.to(
            [1, inner_address, ap_bytes, proofs_checker]
        ))
        address = construct_cr_layer(
            ap_bytes,
            proofs_checker,
            inner_address,  # type: ignore
        ).get_tree_hash_precalc(inner_address)

    elif proofs_checker is not None or len(cr_flag) > 0:
        print("Cannot specify --proofs-checker or --cr-flag without values for --authorized-provider")
        return

    aggregated_signature = G2Element()
    for sig in signature:
        aggregated_signature = AugSchemeMPL.aggregate(
            [aggregated_signature, G2Element.from_bytes(hexstr_to_bytes(sig))]
        )

    aggregated_spend = SpendBundle([], G2Element())
    for bundle in spend:
        aggregated_spend = SpendBundle.aggregate(
            [aggregated_spend, SpendBundle.from_bytes(hexstr_to_bytes(bundle))]
        )

    # Construct the TAIL
    if len(curried_args) > 0:
        curried_tail = tail.curry(*curried_args)
    else:
        curried_tail = tail

    # Construct the intermediate puzzle
    p2_puzzle = Program.to(
        (1, [[51, 0, -113, curried_tail, solution], [51, address, amount, [inner_address]], *extra_conditions])
    )

    # Wrap the intermediate puzzle in a CAT wrapper
    cat_puzzle = construct_cat_puzzle(CAT_MOD, curried_tail.get_tree_hash(), p2_puzzle)
    cat_ph = cat_puzzle.get_tree_hash()

    # Get a signed transaction from the wallet
    signed_tx = await get_signed_tx(
        wallet_rpc_port,
        fingerprint,
        1, #wallet_id
        cat_ph,
        uint64(amount),
        uint64(fee),
        Path(root_path),
    )
    if signed_tx.spend_bundle is None:
        raise ValueError("Error creating signed transaction")
    eve_coin = list(
        filter(lambda c: c.puzzle_hash == cat_ph, signed_tx.spend_bundle.additions())
    )[0]

    # This is where we exit if we're only looking for the selected coin
    if select_coin:
        primary_coin = list(
            filter(
                lambda c: c.name() == eve_coin.parent_coin_info,
                signed_tx.spend_bundle.removals(),
            )
        )[0]
        print(json.dumps(primary_coin.to_json_dict(), sort_keys=True, indent=4))
        print(f"Name: {primary_coin.name().hex()}")
        return

    # Create the CAT spend
    spendable_eve = SpendableCAT(
        eve_coin,
        curried_tail.get_tree_hash(),
        p2_puzzle,
        Program.to([]),
        limitations_solution=solution,
        limitations_program_reveal=curried_tail,
    )
    eve_spend = unsigned_spend_bundle_for_spendable_cats(CAT_MOD, [spendable_eve])

    # Aggregate everything together
    final_bundle = SpendBundle.aggregate(
        [
            signed_tx.spend_bundle,
            eve_spend,
            aggregated_spend,
            SpendBundle([], aggregated_signature),
        ]
    )

    if as_bytes:
        final_bundle_dump = bytes(final_bundle).hex()
    else:
        final_bundle_dump = json.dumps(
            final_bundle.to_json_dict(), sort_keys=True, indent=4
        )

    confirmation = push

    if not quiet:
        confirmation = input(
            "The transaction has been created, would you like to push it to the network? (Y/N)"
        ) in ["y", "Y", "yes", "Yes"]
    if confirmation:
        response = await push_tx(
            wallet_rpc_port, fingerprint, final_bundle, Path(root_path)
        )
        if "error" in response:
            print(f"Error pushing transaction: {response['error']}")
            return
        print("Successfully pushed the transaction to the network")

    print(f"Asset ID: {curried_tail.get_tree_hash().hex()}")
    print(f"Eve Coin ID: {eve_coin.name().hex()}")
    if not confirmation:
        print(f"Spend Bundle: {final_bundle_dump}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
