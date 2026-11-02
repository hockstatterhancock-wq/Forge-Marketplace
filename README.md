# ForgeMarket demo

This repository contains a standalone marketplace demo with local sign-up/sign-in and simulated checkout.

## Run locally

Install Node.js, then double-click `start-marketplace.bat`. The app opens at `http://127.0.0.1:3000/`. Keep the server window open while using it.

The catalog contains India-focused sample materials, indicative sourcing regions, and illustrative INR prices. Verify real prices, specifications, sources, and availability with suppliers. The mock checkout does not process real payments or arrange real delivery. Local accounts and demo orders are written under `backend/data/`; this data is excluded from Git.

## Hosting

This repository is source code only. Pushing it to GitHub does not start the backend or provide a public website. The current server listens only on `127.0.0.1` and stores user/order data in local files, so it needs hosting and a persistent database before it can safely run online.

Do not use this demo backend for real payments or public production accounts.
