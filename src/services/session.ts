import { supabase } from '@/lib/supabase';

/**
 * Report activity to the server, which keeps its own 9-minute idle record
 * (public.touch_session in schema.sql). Returns why the server considers the
 * session over, or null if it is still active.
 *
 * Network errors, or a database without touch_session() yet, return null:
 * the RLS policies stay authoritative either way, and signing a user out
 * because they are briefly offline would be wrong.
 */
export async function touchServerSession(): Promise<'idle' | 'revoked' | null> {
  try {
    const { error } = await supabase.rpc('touch_session');
    if (!error) return null;
    if (error.message.includes('SESSION_EXPIRED')) return 'idle';
    if (error.message.includes('SESSION_REVOKED')) return 'revoked';
    return null;
  } catch {
    return null;
  }
}
