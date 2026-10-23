import { useEffect, useRef } from 'react';
import { ENDED_KEY, IDLE_TIMEOUT_MS, parseEnded, readActivity, readEnded, writeActivity, type EndReason } from '@/lib/session';
import { touchServerSession } from '@/services/session';

/** Input that counts as the user being present. */
const ACTIVITY_EVENTS = ['mousemove', 'mousedown', 'pointerdown', 'keydown', 'wheel', 'scroll', 'touchstart', 'touchmove', 'dragover', 'drop'] as const;
/** Share the latest activity with other tabs at most once a second. */
const STORE_THROTTLE_MS = 1000;
/** Report activity to the server at most every 30 seconds. The server's
 *  deadline is therefore never earlier than this tab's. */
const TOUCH_THROTTLE_MS = 30_000;

/**
 * Ends the session after IDLE_TIMEOUT_MS without input in any tab.
 *
 * One timer per tab, scheduled for the deadline and re-checked when it fires
 * (activity only updates a timestamp). The deadline is also re-checked when a
 * tab becomes visible again or is restored from the back/forward cache,
 * because browsers delay timers in background tabs. Input that arrives after
 * the deadline never revives the session.
 */
export function useIdleTimeout(sid: string | null, onEnd: (reason: EndReason, sid: string, fromOtherTab: boolean) => void) {
  const onEndRef = useRef(onEnd);
  onEndRef.current = onEnd;

  useEffect(() => {
    if (!sid) return;
    let stopped = false;
    let idleTimer: ReturnType<typeof setTimeout> | undefined;
    let storeTimer: ReturnType<typeof setTimeout> | undefined;
    let touchTimer: ReturnType<typeof setTimeout> | undefined;
    let lastStore = 0;
    let lastTouch = 0;

    // A session with no record yet has just signed in.
    let last = readActivity(sid) ?? Date.now();
    if (readActivity(sid) === null) writeActivity(sid, last);

    const stop = () => {
      stopped = true;
      clearTimeout(idleTimer);
      clearTimeout(storeTimer);
      clearTimeout(touchTimer);
      for (const e of ACTIVITY_EVENTS) window.removeEventListener(e, onActivity, true);
      document.removeEventListener('visibilitychange', check);
      window.removeEventListener('focus', check);
      window.removeEventListener('pageshow', check);
      window.removeEventListener('storage', onStorage);
    };

    const end = (reason: EndReason, fromOtherTab = false) => {
      if (stopped) return;
      stop();
      onEndRef.current(reason, sid, fromOtherTab);
    };

    function check() {
      if (stopped) return;
      clearTimeout(idleTimer);
      const shared = readActivity(sid!);
      // 0 is the marker another tab leaves after ending this session.
      if (shared === 0) return end(readEnded(sid!) ?? 'signout', true);
      if (shared !== null && shared > last) last = shared;
      const remaining = last + IDLE_TIMEOUT_MS - Date.now();
      if (remaining <= 0) return end('idle');
      idleTimer = setTimeout(check, remaining);
    }

    const touch = () => {
      clearTimeout(touchTimer);
      touchTimer = undefined;
      lastTouch = Date.now();
      void touchServerSession().then((reason) => {
        if (reason) end(reason);
      });
    };

    function onActivity() {
      if (stopped) return;
      const now = Date.now();
      if (now - last >= IDLE_TIMEOUT_MS) {
        // Possibly past the deadline: decide before counting this input.
        check();
        if (stopped) return;
      }
      last = now;

      if (now - lastStore >= STORE_THROTTLE_MS) {
        lastStore = now;
        writeActivity(sid!, now);
      } else if (!storeTimer) {
        storeTimer = setTimeout(() => {
          storeTimer = undefined;
          lastStore = Date.now();
          writeActivity(sid!, last);
        }, STORE_THROTTLE_MS - (now - lastStore));
      }

      if (now - lastTouch >= TOUCH_THROTTLE_MS) touch();
      else if (!touchTimer) touchTimer = setTimeout(touch, TOUCH_THROTTLE_MS - (now - lastTouch));
    }

    function onStorage(e: StorageEvent) {
      if (e.key !== ENDED_KEY) return;
      const ended = parseEnded(e.newValue);
      if (ended?.sid === sid) end(ended.reason, true);
    }

    for (const e of ACTIVITY_EVENTS) window.addEventListener(e, onActivity, { capture: true, passive: true });
    document.addEventListener('visibilitychange', check);
    window.addEventListener('focus', check);
    window.addEventListener('pageshow', check);
    window.addEventListener('storage', onStorage);

    check();
    // Ask the server right away (page load, new tab, new sign-in).
    if (!stopped) touch();
    return stop;
  }, [sid]);
}
