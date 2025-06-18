from account_manager import AccountManager
from transactions import send_money, handle_withdrawal

def main():
    account_manager = AccountManager()
    logged_in_user_id = None

    while True:
        print("\nWelcome to the Simple Banking System")
        if logged_in_user_id is None:
            print("1. Create Account")
            print("2. Login")
            print("5. Exit")
        else:
            print(f"Welcome, {logged_in_user_id}!")
            print("3. Check Balance")
            print("4. Send Money")
            print("6. Withdraw Money")
            print("7. Logout")
            print("5. Exit")

        choice = input("Enter your choice: ")

        if logged_in_user_id is None:
            if choice == '1':
                user_id = input("Enter user ID for new account: ")
                pin = input("Enter PIN for new account: ")
                if account_manager.create_account(user_id, pin):
                    print("Account created successfully.")
                else:
                    print("Failed to create account. User ID might already exist.")
            elif choice == '2':
                user_id = input("Enter user ID: ")
                pin = input("Enter PIN: ")
                if account_manager.authenticate_user(user_id, pin):
                    logged_in_user_id = user_id
                    print("Login successful.")
                else:
                    print("Invalid credentials.")
            elif choice == '5':
                print("Exiting. Thank you!")
                break
            # else:
            #     # This 'else' is implicitly handled by the outer 'else' for invalid choices
            #     # if not explicitly caught by logged-in user options later
            #     pass

        # Options for logged-in users
        elif logged_in_user_id is not None:
            if choice == '3':
                balance = account_manager.get_balance(logged_in_user_id)
                if balance is not None: # Should always be not None if logged in
                    print(f"Your balance is: {balance}")
                else: # Should not happen if user is properly logged in
                    print("Error: Could not retrieve balance. Please log in again.")
                    logged_in_user_id = None
            elif choice == '4':
                receiver_id = input("Enter receiver's user ID: ")
                try:
                    amount = float(input("Enter amount to send: "))
                    send_money(logged_in_user_id, receiver_id, amount, account_manager)
                except ValueError:
                    print("Invalid amount. Please enter a number.")
            elif choice == '6':
                try:
                    amount = float(input("Enter amount to withdraw: "))
                    handle_withdrawal(logged_in_user_id, amount, account_manager)
                except ValueError:
                    print("Invalid amount. Please enter a number.")
            elif choice == '7':
                logged_in_user_id = None
                print("Logged out.")
            elif choice == '5': # Exit option also available when logged in
                print("Exiting. Thank you!")
                break
            # else:
            #     # This 'else' is implicitly handled by the outer 'else'
            #     pass

        # Handle invalid options not covered by specific states (logged in/out)
        # This needs to be structured carefully to avoid printing "Invalid option" for valid but state-specific choices
        # The current structure: if not logged_in -> choices 1,2,5. if logged_in -> choices 3,4,6,7,5
        # An 'else' here catches anything not 1,2,5 if not logged_in, AND not 3,4,6,7,5 if logged_in.
        else:
            # This handles cases where choice is not 5 and also not one of the
            # active options based on login state.
            # However, the primary 'if/elif choice == ...' should cover valid options.
            # This 'else' will catch choices like '3' when not logged in, or '1' when logged in.
            if choice not in ('1', '2', '3', '4', '5', '6', '7'): # More explicit check for truly invalid options
                 print("Invalid option. Please try again.")
            elif (logged_in_user_id is None and choice in ('3','4','6','7')):
                 print("You need to be logged in to perform this action. Please select option 2 to login.")
            elif (logged_in_user_id is not None and choice in ('1','2')):
                 print("You are already logged in. Please logout first if you want to create a new account or login as different user.")
            # If choice was '5', it's handled, loop breaks.
            # If choice was valid for the state, it's handled.

if __name__ == "__main__":
    main()
