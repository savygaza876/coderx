import unittest
from account_manager import Account, AccountManager
from transactions import send_money, handle_withdrawal

class TestBankingApp(unittest.TestCase):

    def setUp(self):
        """Set up for each test method."""
        self.account_manager = AccountManager()
        # Create some default accounts for testing
        self.account_manager.create_account("user1", "pin123")
        # Set initial balance directly for testing simplicity
        if "user1" in self.account_manager.accounts:
            self.account_manager.accounts["user1"].balance = 1000

        self.account_manager.create_account("user2", "pin456")
        if "user2" in self.account_manager.accounts:
            self.account_manager.accounts["user2"].balance = 500

        self.account_manager.create_account("user3_no_balance", "pin789")
        # user3_no_balance starts with 0 balance by default

    # --- AccountManager Tests ---
    def test_create_account_success(self):
        self.assertTrue(self.account_manager.create_account("new_user", "new_pin"))
        self.assertIn("new_user", self.account_manager.accounts)
        self.assertEqual(self.account_manager.accounts["new_user"].balance, 0)

    def test_create_account_failure_existing_id(self):
        self.assertFalse(self.account_manager.create_account("user1", "another_pin"))

    def test_authenticate_user_success(self):
        self.assertTrue(self.account_manager.authenticate_user("user1", "pin123"))

    def test_authenticate_user_failure_wrong_pin(self):
        self.assertFalse(self.account_manager.authenticate_user("user1", "wrongpin"))

    def test_authenticate_user_failure_non_existent_id(self):
        self.assertFalse(self.account_manager.authenticate_user("non_user", "pin"))

    def test_get_balance_success(self):
        self.assertEqual(self.account_manager.get_balance("user1"), 1000)

    def test_get_balance_non_existent_id(self):
        self.assertIsNone(self.account_manager.get_balance("non_user"))

    def test_get_balance_zero_initial(self):
        self.assertEqual(self.account_manager.get_balance("user3_no_balance"), 0)


    def test_deposit_success(self):
        self.assertTrue(self.account_manager.deposit("user1", 200))
        self.assertEqual(self.account_manager.get_balance("user1"), 1200)

    def test_deposit_failure_non_existent_id(self):
        self.assertFalse(self.account_manager.deposit("non_user", 100))

    def test_deposit_failure_negative_amount(self):
        initial_balance = self.account_manager.get_balance("user1")
        self.assertFalse(self.account_manager.deposit("user1", -50))
        self.assertEqual(self.account_manager.get_balance("user1"), initial_balance) # Balance should not change

    def test_withdraw_success(self):
        self.assertTrue(self.account_manager.withdraw("user1", 300))
        self.assertEqual(self.account_manager.get_balance("user1"), 700)

    def test_withdraw_failure_insufficient_funds(self):
        initial_balance = self.account_manager.get_balance("user2") # user2 has 500
        self.assertFalse(self.account_manager.withdraw("user2", 1000))
        self.assertEqual(self.account_manager.get_balance("user2"), initial_balance) # Balance should not change

    def test_withdraw_failure_non_existent_id(self):
        self.assertFalse(self.account_manager.withdraw("non_user", 100))

    def test_withdraw_failure_negative_amount(self):
        initial_balance = self.account_manager.get_balance("user1")
        self.assertFalse(self.account_manager.withdraw("user1", -50))
        self.assertEqual(self.account_manager.get_balance("user1"), initial_balance)

    # --- Transactions Tests ---
    # Note: For transaction tests, we assume users are "logged in" conceptually,
    # meaning their accounts exist. Authentication is part of AccountManager tests.

    def test_send_money_success(self):
        initial_sender_balance = self.account_manager.get_balance("user1") # 1000
        initial_receiver_balance = self.account_manager.get_balance("user2") # 500

        self.assertTrue(send_money("user1", "user2", 200, self.account_manager))
        self.assertEqual(self.account_manager.get_balance("user1"), initial_sender_balance - 200)
        self.assertEqual(self.account_manager.get_balance("user2"), initial_receiver_balance + 200)

    def test_send_money_failure_insufficient_funds(self):
        initial_sender_balance = self.account_manager.get_balance("user2") # 500
        initial_receiver_balance = self.account_manager.get_balance("user1") # 1000

        self.assertFalse(send_money("user2", "user1", 600, self.account_manager))
        self.assertEqual(self.account_manager.get_balance("user2"), initial_sender_balance)
        self.assertEqual(self.account_manager.get_balance("user1"), initial_receiver_balance)


    def test_send_money_failure_invalid_receiver(self):
        initial_sender_balance = self.account_manager.get_balance("user1")
        self.assertFalse(send_money("user1", "non_existent_receiver", 100, self.account_manager))
        self.assertEqual(self.account_manager.get_balance("user1"), initial_sender_balance)

    def test_send_money_failure_send_to_self(self):
        initial_balance = self.account_manager.get_balance("user1")
        self.assertFalse(send_money("user1", "user1", 100, self.account_manager))
        self.assertEqual(self.account_manager.get_balance("user1"), initial_balance)

    def test_send_money_failure_negative_amount(self):
        initial_sender_balance = self.account_manager.get_balance("user1")
        initial_receiver_balance = self.account_manager.get_balance("user2")
        self.assertFalse(send_money("user1", "user2", -100, self.account_manager))
        self.assertEqual(self.account_manager.get_balance("user1"), initial_sender_balance)
        self.assertEqual(self.account_manager.get_balance("user2"), initial_receiver_balance)

    def test_send_money_failure_sender_does_not_exist(self):
        initial_receiver_balance = self.account_manager.get_balance("user2")
        self.assertFalse(send_money("non_existent_sender", "user2", 100, self.account_manager))
        self.assertEqual(self.account_manager.get_balance("user2"), initial_receiver_balance)

    def test_send_money_refund_scenario(self):
        # This test is tricky because the current AccountManager.deposit always returns True
        # if the account exists and amount is positive. To simulate a deposit failure post-withdrawal,
        # we'd need to modify AccountManager or mock it.
        # For now, we'll test the path where withdrawal succeeds but receiver doesn't exist,
        # which is already covered by test_send_money_failure_invalid_receiver.
        # The refund logic in send_money is:
        #   if account_manager.withdraw(sender_id, amount):
        #       if account_manager.deposit(receiver_id, amount): -> this is the critical part
        #           ...
        #       else: # deposit failed
        #           account_manager.deposit(sender_id, amount) # Refund
        # Since our AccountManager.deposit only fails for non-existent user or negative amount,
        # and receiver_id is checked before, this "else" branch for refunding due to failed deposit
        # (while receiver exists) is hard to trigger without mocking.
        # However, if receiver account was deleted *between* check and deposit, it could happen.

        # Let's simulate the refund path by temporarily "breaking" the receiver's account
        # after withdrawal but before deposit. This is a bit of a hack for testing.
        user1_initial_balance = self.account_manager.get_balance("user1") # 1000
        user2_initial_balance = self.account_manager.get_balance("user2") # 500

        original_deposit_method = self.account_manager.deposit

        def failing_deposit_on_user2(user_id, amount):
            if user_id == "user2":
                return False # Simulate deposit failure for user2
            return original_deposit_method(user_id, amount)

        self.account_manager.deposit = failing_deposit_on_user2

        # Attempt to send money from user1 to user2. Withdrawal from user1 should succeed.
        # Deposit to user2 should fail (due to our mock). Refund to user1 should occur.
        self.assertFalse(send_money("user1", "user2", 100, self.account_manager))

        # user1's balance should be restored to original due to refund
        self.assertEqual(self.account_manager.get_balance("user1"), user1_initial_balance)
        # user2's balance should remain unchanged as the deposit to it failed
        self.assertEqual(self.account_manager.get_balance("user2"), user2_initial_balance)

        self.account_manager.deposit = original_deposit_method # Restore original method


    def test_handle_withdrawal_success(self):
        # User1 has 1000
        self.assertTrue(handle_withdrawal("user1", 100, self.account_manager))
        self.assertEqual(self.account_manager.get_balance("user1"), 900)

    def test_handle_withdrawal_failure_insufficient_funds(self):
        # User2 has 500
        self.assertFalse(handle_withdrawal("user2", 600, self.account_manager))
        self.assertEqual(self.account_manager.get_balance("user2"), 500)

    def test_handle_withdrawal_failure_negative_amount(self):
        initial_balance = self.account_manager.get_balance("user1")
        self.assertFalse(handle_withdrawal("user1", -50, self.account_manager))
        self.assertEqual(self.account_manager.get_balance("user1"), initial_balance)

    def test_handle_withdrawal_failure_non_existent_user(self):
        self.assertFalse(handle_withdrawal("non_existent_user", 50, self.account_manager))


if __name__ == '__main__':
    unittest.main()
