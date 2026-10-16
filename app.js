const FXK = "fx02_key";
const enc = new TextEncoder();
const cat = (a, b) => { const c = new Uint8Array(a.length + b.length); c.set(a); c.set(b, a.length); return c; };
const hex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
const unhex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const sha = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
async function deriveKey(user, pass) {
  const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({name: "PBKDF2", salt: enc.encode(user),
    iterations: 100000, hash: "SHA-256"}, base, 256);
  return new Uint8Array(bits);
}
async function keyOk(key) { return hex(await sha(cat(key, enc.encode("check")))) === FX.check; }
async function decrypt(key) {
  const blob = Uint8Array.from(atob(FX.blob), c => c.charCodeAt(0)), out = new Uint8Array(blob.length);
  for (let i = 0; i < blob.length; i += 32) {
    const ctr = new Uint8Array(4); new DataView(ctr.buffer).setUint32(0, i / 32);
    const ks = await sha(cat(key, ctr));
    for (let j = 0; j < 32 && i + j < blob.length; j++) out[i + j] = blob[i + j] ^ ks[j];
  }
  return JSON.parse(new TextDecoder().decode(out));
}
async function requireData() {
  const h = localStorage.getItem(FXK);
  if (!h || !(await keyOk(unhex(h)))) { location.replace("login.html"); return null; }
  return decrypt(unhex(h));
}
function signOut() { localStorage.removeItem(FXK); location.replace("login.html"); }
function bar(user) { return `<p class="bar">FX02 Ops Reports | Signed in as ${user} | <a href="#" onclick="signOut()">Sign out</a></p>`; }
