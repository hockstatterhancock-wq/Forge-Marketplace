# ForgeMarket local backend

Double-click `start-marketplace.bat` in the parent folder to start the server and open the marketplace in your browser. Close the server window to stop it. Node.js is required; no npm packages or external services are needed.

Sign-up accounts are stored in `backend/data/users.jsonl`. Passwords are hashed with scrypt; plaintext passwords are not stored. Sessions use an HTTP-only, SameSite cookie and are held in memory, so users need to sign in again after the server restarts. The marketplace can still be browsed and checked out as a guest.

The catalog includes India-focused demo materials, indicative Indian sourcing regions, and INR sample prices. These are illustrative only; confirm current market prices, product specifications, origin, and suppliers before purchasing.

Checkout offers clearly labeled simulated UPI and card methods. Completing a mock payment records a demo order in `backend/data/orders.jsonl`; it does not ask for payment credentials, contact a payment provider, or charge money. Demo order totals are calculated by the backend from its product catalog.

This backend is for local demos only. It listens on `127.0.0.1` and does not provide email verification, password reset, HTTPS, or production deployment protections. Do not use it to process real payments.
