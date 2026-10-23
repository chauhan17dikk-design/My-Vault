import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router';
import type { Session, User } from '@supabase/supabase-js';
import { clearRecoverySession, markRecoverySession, purgeLocalAuth, sessionAal, setRememberSession, supabase } from '@/lib/supabase';
import { queryClient } from '@/lib/queryClient';
import { broadcastEnded, isIdleExpired, sessionIdOf, setSessionNotice, writeActivity, type EndReason } from '@/lib/session';
import { useIdleTimeout } from '@/hooks/useIdleTimeout';

interface AuthContextValue {
  session: Session | null;
  user: User | null;
  /** 'aal2' once the authenticator code was verified for this session. */
  aal: 'aal1' | 'aal2' | null;
  loading: boolean;
  signIn: (email: string, password: string, remember: boolean) => Promise<void>;
  signOut: (scope?: 'local' | 'global') => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** Give up waiting for the sign-out request after this long (e.g. offline). */
const SIGN_OUT_TIMEOUT_MS = 5000;

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const sessionRef = useRef(session);
  sessionRef.current = session;
  /** Session ids that have been ended here. They are never restored. */
  const ended = useRef(new Set<string>());

  /**
   * End a session that timed out, was revoked, or ended in another tab:
   * hide protected UI at once, then revoke it on the server and clear the
   * stored tokens. AppLayout then redirects to /login.
   */
  const endSession = useCallback(
    async (reason: EndReason, sid: string, fromOtherTab = false) => {
      if (ended.current.has(sid)) return;
      ended.current.add(sid);
      if (reason !== 'signout') setSessionNotice(reason);
      writeActivity(sid, 0); // marks this session as ended for every tab and reload
      if (!fromOtherTab) broadcastEnded(sid, reason);
      setSession(null);
      setLoading(false);
      queryClient.clear();
      if (window.location.pathname === '/reset-password') navigate('/login', { replace: true });

      // Revokes the refresh token server-side. Bounded so an offline device
      // still drops its tokens.
      const timeout = new Promise<{ error: Error }>((resolve) =>
        setTimeout(() => resolve({ error: new Error('Sign-out timed out') }), SIGN_OUT_TIMEOUT_MS),
      );
      const result = await Promise.race([supabase.auth.signOut({ scope: 'local' }).catch((error: Error) => ({ error })), timeout]);
      if (result.error) {
        // Only drop stored tokens if they still belong to this session (not
        // a new sign-in that happened in the meantime).
        const { data } = await supabase.auth.getSession().catch(() => ({ data: { session: null } }));
        if (!data.session || sessionIdOf(data.session) === sid) purgeLocalAuth();
      }
    },
    [navigate],
  );

  useEffect(() => {
    let mounted = true;
    /** Accept a session from storage or an auth event, unless it already
     *  timed out (reload, or returning to the site after a long time). */
    const accept = (next: Session | null) => {
      if (next) {
        const sid = sessionIdOf(next);
        if (ended.current.has(sid)) return;
        if (isIdleExpired(sid)) {
          void endSession('idle', sid);
          return;
        }
      }
      setSession(next);
      setLoading(false);
    };
    supabase.auth.getSession().then(({ data }) => {
      if (!mounted) return;
      accept(data.session);
    });
    const { data: sub } = supabase.auth.onAuthStateChange((event, next) => {
      accept(next);
      if (event === 'SIGNED_OUT') {
        queryClient.clear();
        clearRecoverySession();
      }
      if (event === 'PASSWORD_RECOVERY') {
        markRecoverySession();
        navigate('/reset-password', { replace: true });
      }
    });
    return () => {
      mounted = false;
      sub.subscription.unsubscribe();
    };
  }, [navigate, endSession]);

  const sid = useMemo(() => (session ? sessionIdOf(session) : null), [session]);
  useIdleTimeout(sid, endSession);

  const signIn = useCallback(async (email: string, password: string, remember: boolean) => {
    setRememberSession(remember);
    const { error } = await supabase.auth.signInWithPassword({ email: email.trim(), password });
    if (error) throw error;
  }, []);

  const signOut = useCallback(async (scope: 'local' | 'global' = 'local') => {
    const current = sessionRef.current;
    const { error } = await supabase.auth.signOut({ scope });
    queryClient.clear();
    if (current) {
      // Other tabs (including ones holding a per-tab session) sign out too.
      const id = sessionIdOf(current);
      writeActivity(id, 0);
      broadcastEnded(id, 'signout');
    }
    if (error) throw error;
  }, []);

  const value = useMemo(
    () => ({ session, user: session?.user ?? null, aal: sessionAal(session), loading, signIn, signOut }),
    [session, loading, signIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}

/** For components rendered only inside protected routes. */
export function useUser(): User {
  const { user } = useAuth();
  if (!user) throw new Error('useUser called without an authenticated user');
  return user;
}
