const status = document.querySelector('#status');

/*
 * STEP 1 — THE WALLET/AUTHENTICATOR CREATES THE PSEUDONYM
 *
 * navigator.credentials.create() asks the WebAuthn authenticator to create a
 * new RP-specific key pair and credential ID. In this demo, the browser plus
 * its authenticator stand in for the Wallet-side WebAuthn capability.
 *
 * The private key remains with the authenticator. It is never sent to the RP.
 */
async function walletCreatesPseudonym(registrationOptions) {
  registrationOptions.challenge = base64urlToBytes(registrationOptions.challenge);
  registrationOptions.user.id = base64urlToBytes(registrationOptions.user.id);
  registrationOptions.excludeCredentials = registrationOptions.excludeCredentials.map(
    credential => ({ ...credential, id: base64urlToBytes(credential.id) }),
  );

  return navigator.credentials.create({ publicKey: registrationOptions });
}

/*
 * STEP 2 — INITIAL REGISTRATION WITH THE RP
 *
 * 1. The client gets a fresh registration challenge and RP information.
 * 2. The simulated Wallet creates the pseudonym credential.
 * 3. The client sends the public registration result to the RP.
 * 4. The RP verifies it and stores the credential ID and public key as P1.
 *
 * See the matching server routes /register/options and /register/verify.
 */
async function registerP1WithRP() {
  status.textContent = 'Waiting for your authenticator…';

  const registrationOptions = await request('/register/options');
  const newPseudonymCredential = await walletCreatesPseudonym(registrationOptions);
  const result = await request('/register/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(credentialToJSON(newPseudonymCredential)),
  });

  status.innerHTML = `Registered <strong>${result.pseudonym}</strong>.<br>RP credential ID: <code>${result.credentialID}</code>`;
}

/*
 * STEP 3 — REUSE P1 AT THE SAME RP
 *
 * navigator.credentials.get() does not create a new pseudonym. The RP limits
 * the request to P1's stored credential ID. The authenticator finds that same
 * credential and signs a fresh challenge with its private key.
 *
 * The RP verifies the signature with P1's stored public key and therefore
 * recognizes the returning controller of P1.
 */
async function reuseP1AtSameRP() {
  status.textContent = 'Waiting for proof from the registered authenticator…';

  const authenticationOptions = await request('/login/options');
  authenticationOptions.challenge = base64urlToBytes(authenticationOptions.challenge);
  authenticationOptions.allowCredentials = authenticationOptions.allowCredentials.map(
    credential => ({ ...credential, id: base64urlToBytes(credential.id) }),
  );

  const existingPseudonymCredential = await navigator.credentials.get({
    publicKey: authenticationOptions,
  });
  const result = await request('/login/verify', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(credentialToJSON(existingPseudonymCredential)),
  });

  status.innerHTML = `<strong>Verified as ${result.pseudonym}.</strong> ${result.message}`;
}

document.querySelector('#register').onclick = () => showErrors('Registration', registerP1WithRP);
document.querySelector('#login').onclick = () => showErrors('Login', reuseP1AtSameRP);

async function showErrors(action, operation) {
  try {
    await operation();
  } catch (error) {
    status.textContent = `${action} failed: ${error.message}`;
  }
}

async function request(url, options) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || response.statusText);
  return data;
}

function base64urlToBytes(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
}

function bytesToBase64url(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// WebAuthn returns binary fields; JSON transport uses base64url strings.
function credentialToJSON(credential) {
  const isRegistration = Boolean(credential.response.attestationObject);
  return {
    id: credential.id,
    rawId: bytesToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: isRegistration
      ? {
          clientDataJSON: bytesToBase64url(credential.response.clientDataJSON),
          attestationObject: bytesToBase64url(credential.response.attestationObject),
          transports: credential.response.getTransports?.() || [],
          publicKeyAlgorithm: credential.response.getPublicKeyAlgorithm?.(),
          publicKey: credential.response.getPublicKey?.()
            ? bytesToBase64url(credential.response.getPublicKey())
            : undefined,
          authenticatorData: credential.response.getAuthenticatorData?.()
            ? bytesToBase64url(credential.response.getAuthenticatorData())
            : undefined,
        }
      : {
          clientDataJSON: bytesToBase64url(credential.response.clientDataJSON),
          authenticatorData: bytesToBase64url(credential.response.authenticatorData),
          signature: bytesToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle
            ? bytesToBase64url(credential.response.userHandle)
            : undefined,
        },
  };
}

