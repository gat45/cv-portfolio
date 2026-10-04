// Documents privés : ce Worker doit être protégé par Cloudflare Access.
// Il valide aussi le JWT Access : ne jamais exposer le bucket R2 publiquement.
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const b64url = (part) => Uint8Array.from(atob(part.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

async function verifyAccess(request, env) {
  const token = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!token) throw new Error('missing_token');
  const [head, body, signature] = token.split('.');
  if (!head || !body || !signature || JSON.parse(new TextDecoder().decode(b64url(head))).alg !== 'RS256') throw new Error('invalid_token');
  const claims = JSON.parse(new TextDecoder().decode(b64url(body)));
  if (claims.exp * 1000 <= Date.now() || !Array.isArray(claims.aud) || !claims.aud.includes(env.ACCESS_AUD) || !claims.email) throw new Error('expired_or_wrong_audience');
  const certificates = await fetch(`https://${env.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`).then((r) => r.json());
  const keyData = certificates.keys.find((key) => key.kid === JSON.parse(new TextDecoder().decode(b64url(head))).kid);
  if (!keyData) throw new Error('unknown_key');
  const key = await crypto.subtle.importKey('jwk', keyData, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64url(signature), new TextEncoder().encode(`${head}.${body}`))) throw new Error('bad_signature');
  return claims;
}

export default {
  async fetch(request, env) {
    if (request.method !== 'GET') return new Response('Method not allowed', { status: 405 });
    let claims; try { claims = await verifyAccess(request, env); } catch { return json({ error: 'access_denied' }, 403); }
    const path = new URL(request.url).pathname;
    if (path === '/api/session') return json({ email: claims.email, expiresAt: claims.exp });
    if (!path.startsWith('/documents/')) return new Response('Not found', { status: 404 });
    const key = path.slice('/documents/'.length);
    if (!/^[a-z0-9][a-z0-9._-]{0,100}$/i.test(key)) return new Response('Not found', { status: 404 });
    const object = await env.DOCUMENTS.get(key);
    if (!object) return new Response('Not found', { status: 404 });
    const headers = new Headers({ 'Cache-Control': 'private, no-store', 'Content-Type': object.httpMetadata?.contentType || 'application/pdf', 'Content-Disposition': `inline; filename="${key.replace(/[^a-z0-9._-]/gi, '_')}"`, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
    return new Response(object.body, { headers });
  },
};
