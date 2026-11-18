// Signup for Sloth Lee Mail. Split out of signup.html because the page CSP is
// `script-src 'self'` with no inline allowance and no hash: the module was inline,
// so the browser blocked it and the form fell back to a native GET submit that put
// the password in the URL. A same-origin file is covered by 'self'.
import { bcrypt, sha256 } from './vendor/hash-wasm.esm.min.js';

// Must match the login client byte for byte: fixed 16-byte salt "OpenNeutronAuth1",
// cost 10, same library. The server stores this token as a one-time setup token.
const AUTH_SALT = new Uint8Array([
  0x4f, 0x70, 0x65, 0x6e, 0x4e, 0x65, 0x75, 0x74,
  0x72, 0x6f, 0x6e, 0x41, 0x75, 0x74, 0x68, 0x31,
]);

const USERNAME_RE = /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/;

const f = document.getElementById('f');
const u = document.getElementById('u');
const p = document.getElementById('p');
const p2 = document.getElementById('p2');
const go = document.getElementById('go');
const m = document.getElementById('m');
const c = document.getElementById('c');
const r = document.getElementById('r');
const re = document.getElementById('re');
const rn = document.getElementById('rn');
const rq = document.getElementById('rq');
const rm = document.getElementById('rm');

const tabCreate = document.getElementById('tab-create');
const tabRequest = document.getElementById('tab-request');
const panelCreate = document.getElementById('panel-create');
const panelRequest = document.getElementById('panel-request');
const title = document.getElementById('title');
const lede = document.getElementById('lede');

const LEDE = {
  create: 'Your password is hashed on this device before it is sent. Your encryption key is generated the first time you sign in — it never reaches the server.',
  request: 'This server approves new mailboxes by hand. Leave an address and you will get an invite code when there is room.',
};

function selectTab(which) {
  const create = which === 'create';
  tabCreate.setAttribute('aria-selected', create ? 'true' : 'false');
  tabRequest.setAttribute('aria-selected', create ? 'false' : 'true');
  panelCreate.hidden = !create;
  panelRequest.hidden = create;
  title.textContent = create ? 'Create your mailbox' : 'Request an invite';
  lede.textContent = LEDE[create ? 'create' : 'request'];
  (create ? u : re).focus({ preventScroll: true });
}

tabCreate.addEventListener('click', () => selectTab('create'));
tabRequest.addEventListener('click', () => selectTab('request'));

function sayIn(node, text, kind) {
  node.textContent = text;
  node.className = 'msg' + (kind ? ' ' + kind : '');
}

r.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = re.value.trim();
  if (!email.includes('@')) { sayIn(rm, 'Enter a valid email address.', 'err'); return; }

  rq.disabled = true;
  sayIn(rm, 'Sending your request…');
  try {
    const res = await fetch('/api/waitlist/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, note: rn.value.trim() }),
    });
    const body = await res.json().catch(() => ({}));
    if (res.ok) {
      sayIn(rm, body.message || 'Request received.', 'ok');
      r.reset();
    } else if (res.status === 429) {
      sayIn(rm, 'Too many requests. Try again later.', 'err');
    } else {
      sayIn(rm, body.error || 'Could not send the request.', 'err');
    }
  } catch {
    sayIn(rm, 'Could not send the request. Try again.', 'err');
  } finally {
    rq.disabled = false;
  }
});

function say(text, kind) {
  m.textContent = text;
  m.className = 'msg' + (kind ? ' ' + kind : '');
}

// Find a nonce whose sha256(challenge + nonce) has `bits` leading zero bits.
// hash-wasm returns a hex string, so the test is on hex nibbles: `bits / 4`
// zero characters, plus a partial nibble when bits is not a multiple of four.
async function solveChallenge(challenge, bits) {
  const wholeNibbles = Math.floor(bits / 4);
  const remainder = bits % 4;
  const zeroPrefix = '0'.repeat(wholeNibbles);
  for (let n = 0; ; n += 1) {
    const hex = await sha256(challenge + String(n));
    let ok = hex.startsWith(zeroPrefix);
    if (ok && remainder > 0) {
      ok = parseInt(hex[wholeNibbles], 16) < (1 << (4 - remainder));
    }
    if (ok) return String(n);
    // Keep the page responsive on slower phones.
    if (n % 8000 === 7999) await new Promise((r) => setTimeout(r, 0));
  }
}

// Set once the server has queued the account: leaves the button inert instead of
// inviting a second submit.
let queued = false;

f.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = u.value.trim().toLowerCase();
  const password = p.value;

  if (!USERNAME_RE.test(username)) {
    say('Use 1-64 characters: lowercase letters, digits, dot, underscore or dash, starting and ending with a letter or digit.', 'err');
    return;
  }
  if (password.length < 8) { say('Use at least 8 characters.', 'err'); return; }
  if (password !== p2.value) { say('Passwords do not match.', 'err'); return; }
  const invite = c.value.trim();

  go.disabled = true;
  say('Deriving your password token (this takes a second)…');

  try {
    const token = await bcrypt({ password, salt: AUTH_SALT, costFactor: 10, outputType: 'encoded' });

    // Proof of work: signup is open to the internet, so each account has to
    // cost something. The server hands out a random challenge; we search for a
    // nonce whose sha256(challenge + nonce) starts with N zero bits.
    say('Checking your browser (a second or two)…');
    const powChallenge = await (await fetch('/api/signup/challenge')).json();
    const nonce = await solveChallenge(powChallenge.challenge, powChallenge.difficulty);

    const res = await fetch('/api/user/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password: token,
        invite_code: invite,
        pow_challenge: powChallenge.challenge,
        pow_nonce: nonce,
      }),
    });
    const body = await res.json().catch(() => ({}));

    if (res.status === 201) {
      say('Account created. Sign in with the same password to finish setting up your key.', 'ok');
      setTimeout(() => { window.location.href = '/login'; }, 1400);
      return;
    }
    // 202: the account exists and is held for approval. It cannot sign in yet,
    // so do not send them to a login form that will only reject the password.
    if (res.status === 202) {
      say('Your account is waiting for approval — you can sign in once it has been accepted. Nothing else is needed from you.', 'ok');
      // The account exists now: a second submit would only answer "name taken".
      queued = true;
      go.textContent = 'Waiting for approval';
      return;
    }
    if (res.status === 409) { say('That mailbox name is already taken.', 'err'); }
    else if (res.status === 403 && body.code === 'invite_required') { say('That invite code is not valid, or it has already been used. Clear the field to create the account without one.', 'err'); }
    else if (res.status === 403) { say('Registration is closed on this server.', 'err'); }
    else if (res.status === 429) { say('Too many attempts. Wait a few minutes and try again.', 'err'); }
    else { say(body.error || 'Could not create the account. Try again.', 'err'); }
  } catch (err) {
    console.error('signup failed', err);
    say('Something went wrong creating the account. Try again.', 'err');
  } finally {
    if (!queued) go.disabled = false;
  }
});
