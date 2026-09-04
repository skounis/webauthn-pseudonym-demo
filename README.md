# ARF-style WebAuthn pseudonym demo

The smallest useful demonstration of one relying party (RP) registering a WebAuthn credential as pseudonym **P1**, then recognizing a later proof made with that credential.

For a detailed explanation of every participant, what is real versus simulated, and the complete registration/login sequence, read **[Flow and simulation guide](./FLOW.md)**.

## Run

Requires Node.js 20 or newer and a WebAuthn-capable browser/authenticator.

```sh
npm install
npm start
```

Open <http://localhost:3000>, select **Register P1**, and then **Log in as P1**. `localhost` is accepted as a secure WebAuthn context for development.

The credential and challenges are kept only in server memory. Restarting the server resets the demo, so delete the corresponding passkey in your browser/OS if you want a completely clean rerun.

## What happens

The browser-side flow is separated into [`app.js`](./app.js), where the three stages are labelled in the code:

1. `walletCreatesPseudonym()` simulates the Wallet-side operation. WebAuthn creates an RP-scoped credential and keeps its private key in the authenticator.
2. `registerP1WithRP()` sends the public registration response to the RP. The RP verifies and stores the credential ID, public key, and signature counter as `P1`.
3. `reuseP1AtSameRP()` asks the authenticator to reuse that credential. It signs a fresh challenge, which the RP verifies using P1's stored public key.

Before stage 1, the RP creates an opaque random user handle and registration challenge. The user handle contains no PID, name, or email. It is registration input, not the cryptographic pseudonym itself.

This demonstrates **pseudonymous continuity**: the RP can recognize control of the same registered credential. It is intentionally not a complete EUDI Wallet implementation and does **not** establish anonymity, legal identity, PID/attribute binding, Wallet Unit authenticity, attestation/revocation status, or production-grade persistence/session security. A synced passkey may also be usable from another device, so “same credential controller” is more precise than “same physical Wallet Unit.”

The design mirrors the ARF Topic E initial WebAuthn/FIDO2 concept: a public key and related credential ID constitute the RP-specific pseudonym. `attestationType: 'none'` keeps this educational demo focused on credential continuity rather than authenticator provenance.

