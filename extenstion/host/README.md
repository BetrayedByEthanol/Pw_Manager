# Vaulty native host mock

Temporary native messaging host for testing the browser-extension bridge.

It handles:

- `GENERATE_PASSWORD`
- `RETRIEVE_CREDENTIAL`
- `SAVE_CREDENTIAL`
- `CHECK_LOCK_STATE`
- `CHECK_DUPLICATE_CREDENTIAL`

This mock must later be replaced with a thin relay to the Vaulty daemon.
