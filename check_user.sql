-- Check if user exists
SELECT customer_id, customer_name, customer_email, 
       LEFT(customer_password, 20) AS hash_preview,
       account_number, bank_balance
FROM bank_users
WHERE customer_email = 'ku@gmail.com';

-- Show all users
SELECT customer_id, customer_name, customer_email, account_number FROM bank_users;
