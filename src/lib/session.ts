import type { Session } from '@supabase/supabase-js';

/** Sign out after this long without user input. Keep in sync with
 *  public.session_idle_limit() in supabase/schema.sql. */
export const IDLE_TIMEOUT_MS = 9 * 60 * 1000;

export const IDLE_EXPIRED_MESSAGE = 'Your session has expired due to 9 minutes of inactivity. Please log in again to continue.';
export const REVOKED_MESSAGE = 'Your session has ended. Please log in again to continue.';

/** Why a session ended without the user signing out in this tab. */
export type EndReason = 'idle' | 'revoked' | 'signout';

// Shared by every tab of the app (localStorage). Neither holds a credential.
const ACTIVITY_KEY = 'vault.last-activity';
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

interface ActivityRecord {
  sid: string;
  at: number;
}

/** Last user activity for this session in any tab, or null if unknown. */
export function readActivity(sid: string): number | null {
  return safe(() => {
    const rec = JSON.parse(localStorage.getItem(ACTIVITY_KEY) ?? 'null') as ActivityRecord | null;
    return rec && rec.sid === sid && typeof rec.at === 'number' ? rec.at : null;
  }, null);
}

export function writeActivity(sid: string, at: number) {
  safe(() => {
    // Never move another tab's newer timestamp backwards.
    const prev = readActivity(sid);
    if (prev !== null && prev >= at && at !== 0) return;
    localStorage.setItem(ACTIVITY_KEY, JSON.stringify({ sid, at } satisfies ActivityRecord));
  }, undefined);
}

/** True when this session is known to have been idle past the limit (or was
 *  ended), e.g. on a reload or when returning to a long-hidden tab. */
export function isIdleExpired(sid: string, now = Date.now()): boolean {
  const at = readActivity(sid);
  return at !== null && now - at >= IDLE_TIMEOUT_MS;
}

/** Tell other tabs this session is over (they receive a `storage` event). */
export function broadcastEnded(sid: string, reason: EndReason) {
  safe(() => localStorage.setItem(ENDED_KEY, JSON.stringify({ sid, reason, at: Date.now() })), undefined);
}

export function parseEnded(value: string | null): { sid: string; reason: EndReason } | null {
  return safe(() => {
    const v = JSON.parse(value ?? 'null') as { sid?: unknown; reason?: unknown } | null;
    if (!v || typeof v.sid !== 'string') return null;
    const reason: EndReason = v.reason === 'idle' || v.reason === 'revoked' ? v.reason : 'signout';
    return { sid: v.sid, reason };
  }, null);
}

/** Why this session ended in another tab, if it did. */
export function readEnded(sid: string): EndReason | null {
  const ended = parseEnded(safe(() => localStorage.getItem(ENDED_KEY), null));
  return ended && ended.sid === sid ? ended.reason : null;
}

export interface SessionNotice {
  reason: 'idle' | 'revoked';
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
    return notice && (notice.reason === 'idle' || notice.reason === 'revoked') ? notice : null;
  }, null);
}
