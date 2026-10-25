import type { Session } from '@supabase/supabase-js';

/** Every session ends this long after sign-in, whatever the user is doing.
 *  Keep in sync with public.session_max_age() in supabase/schema.sql. */
export const SESSION_MAX_AGE_MS = 5 * 60 * 1000;

export const SESSION_EXPIRED_MESSAGE =
  'Your session has expired. For your security you are signed out 5 minutes after signing in. Please log in again to continue.';
export const REVOKED_MESSAGE = 'Your session has ended. Please log in again to continue.';

/** Why a session ended without the user signing out in this tab. */
export type EndReason = 'timeout' | 'revoked' | 'signout';

// Shared by every tab of the app (localStorage). Neither holds a credential.
const START_KEY = 'vault.session-start';
export const ENDED_KEY = 'vault.session-ended';
// Per tab (sessionStorage): the notice the login page shows once.
const NOTICE_KEY = 'vault.session-notice';

function safe<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

/** The Supabase session id (`session_id` JWT claim) the server tracks.
 *  Falls back to the user id for tokens without one. */
export function sessionIdOf(session: Session): string {
  return safe(() => {
    const payload = session.access_token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(atob(payload.padEnd(Math.ceil(payload.length / 4) * 4, '='))) as { session_id?: unknown };
    return typeof claims.session_id === 'string' && claims.session_id ? claims.session_id : session.user.id;
  }, session.user.id);
}

interface StartRecord {
  sid: string;
  at: number;
}

/** When this session signed in (local clock, shared by all tabs), or null
 *  if unknown. 0 means the session was ended. */
export function readSessionStart(sid: string): number | null {
  return safe(() => {
    const rec = JSON.parse(localStorage.getItem(START_KEY) ?? 'null') as StartRecord | null;
    return rec && rec.sid === sid && typeof rec.at === 'number' ? rec.at : null;
  }, null);
}

export function writeSessionStart(sid: string, at: number) {
  safe(() => localStorage.setItem(START_KEY, JSON.stringify({ sid, at } satisfies StartRecord)), undefined);
}

/** True when this session is known to be past its 5 minutes (or was ended),
 *  e.g. on a reload or when returning to a hidden tab. */
export function isSessionExpired(sid: string, now = Date.now()): boolean {
  const at = readSessionStart(sid);
  return at !== null && now - at >= SESSION_MAX_AGE_MS;
}

/** Tell other tabs this session is over (they receive a `storage` event). */
export function broadcastEnded(sid: string, reason: EndReason) {
  safe(() => localStorage.setItem(ENDED_KEY, JSON.stringify({ sid, reason, at: Date.now() })), undefined);
}

export function parseEnded(value: string | null): { sid: string; reason: EndReason } | null {
  return safe(() => {
    const v = JSON.parse(value ?? 'null') as { sid?: unknown; reason?: unknown } | null;
    if (!v || typeof v.sid !== 'string') return null;
    const reason: EndReason = v.reason === 'timeout' || v.reason === 'revoked' ? v.reason : 'signout';
    return { sid: v.sid, reason };
  }, null);
}

/** Why this session ended in another tab, if it did. */
export function readEnded(sid: string): EndReason | null {
  const ended = parseEnded(safe(() => localStorage.getItem(ENDED_KEY), null));
  return ended && ended.sid === sid ? ended.reason : null;
}

export interface SessionNotice {
  reason: 'timeout' | 'revoked';
  uploadsInterrupted?: boolean;
}

export function setSessionNotice(reason: SessionNotice['reason']) {
  safe(() => sessionStorage.setItem(NOTICE_KEY, JSON.stringify({ reason } satisfies SessionNotice)), undefined);
}

/** Called when uploads are stopped because the session ended. */
export function markUploadsInterrupted() {
  safe(() => {
    const notice = JSON.parse(sessionStorage.getItem(NOTICE_KEY) ?? 'null') as SessionNotice | null;
    if (notice) sessionStorage.setItem(NOTICE_KEY, JSON.stringify({ ...notice, uploadsInterrupted: true }));
  }, undefined);
}

/** Read and clear the pending notice, so it is shown exactly once. */
export function takeSessionNotice(): SessionNotice | null {
  return safe(() => {
    const raw = sessionStorage.getItem(NOTICE_KEY);
    sessionStorage.removeItem(NOTICE_KEY);
    const notice = JSON.parse(raw ?? 'null') as SessionNotice | null;
    return notice && (notice.reason === 'timeout' || notice.reason === 'revoked') ? notice : null;
  }, null);
}
