from account_manager import AccountManager

def send_money(sender_id: str, receiver_id: str, amount: float, account_manager: AccountManager) -> bool:
    """Sends money from sender's account to receiver's account."""
    if amount <= 0:
        print("Transaction failed. Amount must be positive.")
        return False
    if sender_id == receiver_id:
        print("Transaction failed. Sender and receiver cannot be the same.")
        return False
    if account_manager.get_balance(receiver_id) is None:
        print("Transaction failed. Receiver account does not exist.")
        return False

    if account_manager.withdraw(sender_id, amount):
        if account_manager.deposit(receiver_id, amount):
            print("Transaction successful.")
            return True
        else:
            # This case should ideally not happen if receiver_id was validated
            # but included for robustness.
            print("Failed to credit receiver. Refunding sender.")
            account_manager.deposit(sender_id, amount) # Refund sender
            return False
    else:
        print("Transaction failed. Sender has insufficient funds or sender account does not exist.")
        return False

def handle_withdrawal(user_id: str, amount: float, account_manager: AccountManager) -> bool:
    """Handles withdrawal of money from a user's account."""
    if amount <= 0:
        print("Withdrawal amount must be positive.")
        return False

    if account_manager.withdraw(user_id, amount):
        print(f"Withdrawal of {amount} successful for user {user_id}.")
        return True
    else:
        print(f"Withdrawal of {amount} failed for user {user_id}. Check balance or account validity.")
        return False
