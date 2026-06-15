# Migration from Telegram

Earlier versions of Hushbox used Telegram Bot API as a transport mechanism.

Current versions use a dedicated relay layer or manual ciphertext exchange instead.

## Migration Notes

- Legacy contact data may still contain `telegram_bot_token`.
- Legacy contact data may still contain `telegram_chat_id`.
- These fields are retained only for migration compatibility.
- They are not used by the current client transport flow.

## Recommended Cleanup

After confirming migration is complete:

1. Back up your local contact data.
2. Remove legacy Telegram fields from stored contacts.
3. Save the cleaned contact file.
4. Test relay-based or manual delivery with a non-critical contact first.