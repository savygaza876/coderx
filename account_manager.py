class Account:
    def __init__(self, user_id, pin, balance=0):
        self.user_id = user_id
        self.pin = pin
        self.balance = balance

class AccountManager:
    def __init__(self):
        self.accounts = {}

    def create_account(self, user_id, pin):
        if user_id in self.accounts:
            return False
        new_account = Account(user_id, pin)
        self.accounts[user_id] = new_account
        return True

    def authenticate_user(self, user_id, pin):
        if user_id in self.accounts:
            account = self.accounts[user_id]
            if account.pin == pin:
                return True
        return False

    def get_balance(self, user_id):
        if user_id in self.accounts:
            account = self.accounts[user_id]
            return account.balance
        return None

    def deposit(self, user_id, amount):
        if user_id in self.accounts and amount > 0:
            account = self.accounts[user_id]
            account.balance += amount
            return True
        return False

    def withdraw(self, user_id, amount):
        if user_id in self.accounts and amount > 0:
            account = self.accounts[user_id]
            if account.balance >= amount:
                account.balance -= amount
                return True
        return False
