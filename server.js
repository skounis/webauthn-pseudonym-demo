import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

const port = Number(process.env.PORT || 3000);
const rpID = 'localhost';
const origin = `http://${rpID}:${port}`;

// One in-memory RP record. Restarting the server deliberately clears it.
const p1 = {
  alias: 'P1',
  userID: randomBytes(32), // opaque; contains no name, email, or PID
  registrationChallenge: undefined,
  authenticationChallenge: undefined,
  credential: undefined,
};

const json = (res, status, body) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

async function body(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

const server = createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/') {
      const html = await readFile(new URL('./index.html', import.meta.url));
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return res.end(html);
    }

    if (req.method === 'GET' && req.url === '/app.js') {
      const javascript = await readFile(new URL('./app.js', import.meta.url));
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8' });
      return res.end(javascript);
    }

    // STEP 2A: The RP gives its identity and a fresh challenge to the client.
    if (req.method === 'GET' && req.url === '/register/options') {
      const options = await generateRegistrationOptions({
        rpName: 'ARF Pseudonym Demo RP',
        rpID,
        userID: p1.userID,
        userName: p1.alias,
        userDisplayName: 'Pseudonym P1',
        attestationType: 'none',
        excludeCredentials: p1.credential ? [{ id: p1.credential.id }] : [],
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        supportedAlgorithmIDs: [-7, -257],
      });
      p1.registrationChallenge = options.challenge;
      return json(res, 200, options);
    }

    // STEP 2B: The RP verifies and stores the Wallet-created pseudonym as P1.
    if (req.method === 'POST' && req.url === '/register/verify') {
      if (!p1.registrationChallenge) throw new Error('Start registration first.');
      const response = await body(req);
      const result = await verifyRegistrationResponse({
        response,
        expectedChallenge: p1.registrationChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        supportedAlgorithmIDs: [-7, -257],
      });
      p1.registrationChallenge = undefined;
      if (!result.verified || !result.registrationInfo) throw new Error('Registration was not verified.');
      // RP-visible pseudonym material: credential ID + public key + counter.
      // The matching private key never leaves the Wallet/authenticator.
      p1.credential = result.registrationInfo.credential;
      return json(res, 200, { verified: true, pseudonym: p1.alias, credentialID: p1.credential.id });
    }

    // STEP 3A: Ask specifically for the credential previously stored as P1.
    if (req.method === 'GET' && req.url === '/login/options') {
      if (!p1.credential) return json(res, 409, { error: 'Register P1 first.' });
      const options = await generateAuthenticationOptions({
        rpID,
        allowCredentials: [{ id: p1.credential.id, transports: p1.credential.transports }],
        userVerification: 'preferred',
      });
      p1.authenticationChallenge = options.challenge;
      return json(res, 200, options);
    }

    // STEP 3B: Verify P1's signature over the new challenge.
    if (req.method === 'POST' && req.url === '/login/verify') {
      if (!p1.credential || !p1.authenticationChallenge) throw new Error('Start login first.');
      const response = await body(req);
      if (response.id !== p1.credential.id) throw new Error('Unknown pseudonym credential.');
      const result = await verifyAuthenticationResponse({
        response,
        expectedChallenge: p1.authenticationChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: p1.credential,
      });
      p1.authenticationChallenge = undefined;
      if (!result.verified) throw new Error('Authentication was not verified.');
      p1.credential.counter = result.authenticationInfo.newCounter;
      return json(res, 200, { verified: true, pseudonym: p1.alias, message: 'Same registered credential proved again.' });
    }

    return json(res, 404, { error: 'Not found' });
  } catch (error) {
    console.error(error);
    return json(res, 400, { error: error.message });
  }
});

server.listen(port, () => console.log(`ARF pseudonym demo: ${origin}`));

