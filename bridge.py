from web3 import Web3
from web3.contract import Contract
from web3.providers.rpc import HTTPProvider
from web3.middleware import geth_poa_middleware
import json
import sys
from pathlib import Path
from eth_account import Account
import eth_account

source_chain = 'avax'
destination_chain = 'bsc'
contract_info = "contract_info.json"

def connectTo(chain):
    """Connect to specific blockchain network"""
    if chain == 'avax':
        api_url = "https://api.avax-test.network/ext/bc/C/rpc"
    if chain == 'bsc':
        api_url = "https://data-seed-prebsc-1-s1.binance.org:8545/"
    
    if chain in ['avax','bsc']:
        w3 = Web3(Web3.HTTPProvider(api_url))
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    return w3

def getContractInfo(chain):
    """Load contract information from JSON file"""
    p = Path(__file__).with_name(contract_info)
    try:
        with p.open('r') as f:
            contracts = json.load(f)
    except Exception as e:
        print(f"Failed to read contract info: {e}")
        sys.exit(1)
    return contracts[chain]

def load_warden_account():
    """Load the warden's private key and create account"""
    try:
        with open("eth_mnemonic.txt", "r") as f:
            private_key = f.read().strip()
        return Account.from_key(private_key)
    except Exception as e:
        print(f"Failed to load warden account: {e}")
        sys.exit(1)

def get_wrapped_token(dest_contract, underlying_token):
    """Get wrapped token address for a given underlying token"""
    try:
        return dest_contract.functions.wrapped_tokens(underlying_token).call()
    except Exception:
        return None

def handle_deposit_event(w3_source, w3_dest, source_contract, dest_contract, warden_account, event):
    """Handle Deposit events from source chain by calling wrap on destination"""
    try:
        token = event.args.token
        recipient = event.args.recipient
        amount = event.args.amount

        # Validation checks
        if not Web3.is_address(token) or not Web3.is_address(recipient):
            print(f"Invalid address in Deposit event: token={token}, recipient={recipient}")
            return
        if amount <= 0:
            print(f"Invalid amount in Deposit event: {amount}")
            return

        # Build wrap transaction
        nonce = w3_dest.eth.get_transaction_count(warden_account.address)
        
        wrap_txn = dest_contract.functions.wrap(
            token,
            recipient,
            amount
        ).build_transaction({
            'from': warden_account.address,
            'nonce': nonce,
            'gas': 200000,
            'gasPrice': w3_dest.eth.gas_price,
            'chainId': w3_dest.eth.chain_id
        })
        
        # Sign and send transaction
        signed_txn = warden_account.sign_transaction(wrap_txn)
        tx_hash = w3_dest.eth.send_raw_transaction(signed_txn.rawTransaction)
        receipt = w3_dest.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt.status == 1:
            print(f"Successfully processed Deposit event. Wrap tx: {tx_hash.hex()}")
        else:
            print(f"Wrap transaction failed: {tx_hash.hex()}")
            
    except Exception as e:
        print(f"Error processing Deposit event: {e}")

def handle_unwrap_event(w3_source, w3_dest, source_contract, dest_contract, warden_account, event):
    """Handle Unwrap events from destination chain by calling withdraw on source"""
    try:
        underlying_token = event.args.underlying_token
        from_addr = event.args.frm
        to_addr = event.args.to
        amount = event.args.amount

        # Validation checks
        if not Web3.is_address(underlying_token) or not Web3.is_address(to_addr):
            print(f"Invalid address in Unwrap event: token={underlying_token}, to={to_addr}")
            return
        if amount <= 0:
            print(f"Invalid amount in Unwrap event: {amount}")
            return

        # Build withdraw transaction
        nonce = w3_source.eth.get_transaction_count(warden_account.address)
        
        withdraw_txn = source_contract.functions.withdraw(
            underlying_token,
            to_addr,
            amount
        ).build_transaction({
            'from': warden_account.address,
            'nonce': nonce,
            'gas': 200000,
            'gasPrice': w3_source.eth.gas_price,
            'chainId': w3_source.eth.chain_id
        })
        
        # Sign and send transaction
        signed_txn = warden_account.sign_transaction(withdraw_txn)
        tx_hash = w3_source.eth.send_raw_transaction(signed_txn.rawTransaction)
        receipt = w3_source.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt.status == 1:
            print(f"Successfully processed Unwrap event. Withdraw tx: {tx_hash.hex()}")
        else:
            print(f"Withdraw transaction failed: {tx_hash.hex()}")
            
    except Exception as e:
        print(f"Error processing Unwrap event: {e}")

def scanBlocks(chain):
    """Scan blocks for events and handle cross-chain communication"""
    if chain not in ['source', 'destination']:
        print(f"Invalid chain: {chain}")
        return
        
    try:
        # Connect to both chains
        w3_source = connectTo('avax')
        w3_dest = connectTo('bsc')
        
        # Load contract info
        source_info = getContractInfo('source')
        dest_info = getContractInfo('destination')
        
        # Create contract instances
        source_contract = w3_source.eth.contract(
            address=source_info['address'],
            abi=source_info['abi']
        )
        dest_contract = w3_dest.eth.contract(
            address=dest_info['address'],
            abi=dest_info['abi']
        )
        
        # Load warden account
        warden_account = load_warden_account()
        
        # Get current block numbers
        current_block_source = w3_source.eth.block_number
        current_block_dest = w3_dest.eth.block_number
        
        # Scan last 5 blocks
        if chain == 'source':
            fromBlock = max(current_block_source - 5, 0)
            deposit_filter = source_contract.events.Deposit.create_filter(
                fromBlock=fromBlock
            )
            
            for event in deposit_filter.get_all_entries():
                handle_deposit_event(
                    w3_source, w3_dest,
                    source_contract, dest_contract,
                    warden_account, event
                )
                
        elif chain == 'destination':
            fromBlock = max(current_block_dest - 5, 0)
            unwrap_filter = dest_contract.events.Unwrap.create_filter(
                fromBlock=fromBlock
            )
            
            for event in unwrap_filter.get_all_entries():
                handle_unwrap_event(
                    w3_source, w3_dest,
                    source_contract, dest_contract,
                    warden_account, event
                )
                
    except Exception as e:
        print(f"Error scanning blocks: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Please specify which chain to scan ('source' or 'destination')")
        sys.exit(1)
    
    chain = sys.argv[1]
    scanBlocks(chain)
