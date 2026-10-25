import { useEffect, useRef } from 'react';
import { ENDED_KEY, SESSION_MAX_AGE_MS, parseEnded, readEnded, readSessionStart, writeSessionStart, type EndReason } from '@/lib/session';
import { touchServerSession } from '@/services/session';

/** Ask the server about the session at most this often (on load, focus and
 *  when a tab becomes visible). */
const SERVER_CHECK_MS = 30_000;

/**
 * Ends the session SESSION_MAX_AGE_MS after sign-in. User activity does not
 * extend it.
 *
 * One timer per tab, set for the deadline. The deadline is re-checked when a
 * tab becomes visible, gets focus or is restored from the back/forward cache,
 * because browsers delay timers in background tabs. The server enforces the
 * same limit from the session's own sign-in time.
 */
export function useSessionTimeout(sid: string | null, onEnd: (reason: EndReason, sid: string, fromOtherTab: boolean) => void) {
  const onEndRef = useRef(onEnd);
  onEndRef.current = onEnd;

  useEffect(() => {
    if (!sid) return;
    const id = sid;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let lastServerCheck = 0;

    // A session with no record yet has just signed in.
    let start = readSessionStart(id);
    if (start === null) {
      start = Date.now();
      writeSessionStart(id, start);
    }

    const stop = () => {
      stopped = true;
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', onReturn);
      window.removeEventListener('focus', onReturn);
      window.removeEventListener('pageshow', onReturn);
      window.removeEventListener('storage', onStorage);
    };

    const end = (reason: EndReason, fromOtherTab = false) => {
      if (stopped) return;
      stop();
      onEndRef.current(reason, id, fromOtherTab);
    };

    function check() {
      if (stopped) return;
      clearTimeout(timer);
      const shared = readSessionStart(id);
      // 0 is the marker another tab leaves after ending this session.
      if (shared === 0) return end(readEnded(id) ?? 'signout', true);
      // Another tab may have seen this session first: the earliest start wins.
      if (shared !== null && shared < start!) start = shared;
      const remaining = start! + SESSION_MAX_AGE_MS - Date.now();
      if (remaining <= 0) return end('timeout');
      timer = setTimeout(check, remaining);
    }

    function askServer() {
      if (stopped || Date.now() - lastServerCheck < SERVER_CHECK_MS) return;
      lastServerCheck = Date.now();
      void touchServerSession().then((reason) => {
        if (reason) end(reason);
      });
    }

    function onReturn() {
      check();
      askServer();
    }

    function onStorage(e: StorageEvent) {
      if (e.key !== ENDED_KEY) return;
      const ended = parseEnded(e.newValue);
      if (ended?.sid === id) end(ended.reason, true);
    }

    document.addEventListener('visibilitychange', onReturn);
    window.addEventListener('focus', onReturn);
    window.addEventListener('pageshow', onReturn);
    window.addEventListener('storage', onStorage);

    check();
    askServer();
    return stop;
  }, [sid]);
}
