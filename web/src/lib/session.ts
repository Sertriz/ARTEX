// The browser's one policy for a 401 from the API. This module imports nothing,
// so node --test can load it (scripts/session.test.mjs); the browser specifics
// come in through SessionDeps (see browserSession in api.ts).

// A 401 from these paths answers the credentials in the request body (a wrong
// password or setup token), not an expired session: the page shows the error.
const CREDENTIAL_PATHS = new Set(["/auth/login", "/auth/init"]);

export interface SessionDeps {
  /** The token stored now (localStorage), or null. */
  readToken(): string | null;
  /** Forget the stored token. */
  clearToken(): void;
  /** Leave for the login page. */
  toLogin(): void;
}

/** isCredentialPath reports whether a 401 from path is an answer, not a sign-out. path is relative to /api. */
export function isCredentialPath(path: string): boolean {
  return CREDENTIAL_PATHS.has(path.split("?")[0]);
}

/**
 * sendWithSession sends a request with the stored token and applies the 401
 * policy to the response:
 * - a 401 from /auth/login or /auth/init goes back to the caller untouched;
 * - when the stored token has meanwhile changed to another non-empty one (a
 *   login in this tab or another), the request is sent once more with it;
 * - otherwise signOut runs with the token that was sent.
 * Any other status, 503 included, goes back untouched: only a 401 signs out.
 */
export async function sendWithSession<R extends { status: number }>(
  path: string,
  send: (token: string | null) => Promise<R>,
  deps: SessionDeps,
): Promise<R> {
  let sent = storedToken(deps);
  let response = await send(sent);
  if (response.status !== 401 || isCredentialPath(path)) return response;
  const current = storedToken(deps);
  if (current && current !== sent) {
    sent = current;
    response = await send(sent);
    if (response.status !== 401) return response;
  }
  signOut(sent, deps);
  return response;
}

/**
 * signOut removes the stored token only if it is still the one that was
 * rejected, so a token another tab stored in the meantime survives, then
 * leaves for the login page.
 */
export function signOut(rejected: string | null, deps: SessionDeps): void {
  if (storedToken(deps) === rejected) deps.clearToken();
  deps.toLogin();
}

// storedToken is the stored token with "" read as none.
function storedToken(deps: SessionDeps): string | null {
  const token = deps.readToken();
  return token ? token : null;
}
