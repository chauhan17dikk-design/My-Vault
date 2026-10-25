import { supabase } from '@/lib/supabase';

/**
 * Ask the server whether this session is still within its 5 minutes
 * (public.touch_session in schema.sql). Returns why the server considers the
 * session over, or null if it is still active.
 *
 * Network errors, or a database without touch_session() yet, return null:
 * the RLS policies stay authoritative either way, and signing a user out
 * because they are briefly offline would be wrong.
 */
export async function touchServerSession(): Promise<'timeout' | 'revoked' | null> {
  try {
    const { error } = await supabase.rpc('touch_session');
    if (!error) return null;
    if (error.message.includes('SESSION_EXPIRED')) return 'timeout';
    if (error.message.includes('SESSION_REVOKED')) return 'revoked';
    return null;
  } catch {
    return null;
  }
}
