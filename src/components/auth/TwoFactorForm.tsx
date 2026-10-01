import { useEffect, useRef, useState, type FormEvent } from 'react';
import { AlertCircle, KeyRound, Smartphone } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Field, Input } from '@/components/ui/Input';
import { Spinner } from '@/components/ui/misc';
import { supabase } from '@/lib/supabase';
import { getErrorMessage } from '@/lib/errors';

type Setup =
  | { kind: 'loading' }
  | { kind: 'verify'; factorId: string }
  | { kind: 'enroll'; factorId: string; qr: string; secret: string }
  | { kind: 'error'; message: string };

/**
 * Second sign-in step. With a verified authenticator it asks for the current
 * 6-digit code; without one it enrols a new authenticator (QR code) first.
 * Supabase only allows enrolling at aal1 while no verified factor exists, so
 * a password alone can never add a second authenticator.
 */
export function TwoFactorForm({ onVerified }: { onVerified: () => void }) {
  const [setup, setSetup] = useState<Setup>({ kind: 'loading' });
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    // StrictMode runs effects twice in development; enrol only once.
    if (started.current) return;
    started.current = true;
    (async () => {
      const { data, error } = await supabase.auth.mfa.listFactors();
      if (error) throw error;
      const verified = data.totp[0];
      if (verified) return setSetup({ kind: 'verify', factorId: verified.id });
      // Drop half-finished enrolments so a fresh QR code can be issued.
      for (const f of data.all) {
        if (f.status === 'unverified') await supabase.auth.mfa.unenroll({ factorId: f.id });
      }
      const enrolled = await supabase.auth.mfa.enroll({ factorType: 'totp', issuer: 'My Vault', friendlyName: `Authenticator ${Date.now()}` });
      if (enrolled.error) throw enrolled.error;
      setSetup({ kind: 'enroll', factorId: enrolled.data.id, qr: enrolled.data.totp.qr_code, secret: enrolled.data.totp.secret });
    })().catch((err) => setSetup({ kind: 'error', message: getErrorMessage(err, 'Could not start two-step verification.') }));
  }, []);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (setup.kind !== 'verify' && setup.kind !== 'enroll') return;
    if (!/^\d{6}$/.test(code)) return setError('Enter the 6-digit code from your authenticator app.');
    setVerifying(true);
    setError(null);
    const { error } = await supabase.auth.mfa.challengeAndVerify({ factorId: setup.factorId, code });
    setVerifying(false);
    if (error) {
      setCode('');
      return setError(getErrorMessage(error));
    }
    onVerified();
  };

  if (setup.kind === 'loading') {
    return (
      <div className="flex justify-center py-10">
        <Spinner className="size-6" />
      </div>
    );
  }
  if (setup.kind === 'error') {
    return (
      <div role="alert" className="flex items-start gap-2.5 rounded-xl border border-danger/30 bg-danger-soft p-3 text-sm text-danger">
        <AlertCircle className="mt-0.5 size-4 shrink-0" />
        <span>{setup.message}</span>
      </div>
    );
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4" noValidate>
      {setup.kind === 'enroll' && (
        <div className="space-y-3 rounded-xl border border-line p-4 text-sm text-muted">
          <p className="flex items-start gap-2 text-ink">
            <Smartphone className="mt-0.5 size-4 shrink-0" />
            <span>
              Scan this QR code with an authenticator app (Google Authenticator, Microsoft Authenticator or Authy). From now on every sign-in
              needs your password <strong>and</strong> a code from this phone.
            </span>
          </p>
          <img src={setup.qr} alt="QR code for your authenticator app" className="mx-auto size-48 rounded-lg bg-white p-2" />
          <p>
            Can’t scan? Enter this key manually:
            <code className="mt-1 block rounded-lg bg-canvas p-2 text-center font-mono text-xs break-all text-ink select-all">{setup.secret}</code>
          </p>
        </div>
      )}
      {error && (
        <div role="alert" className="flex items-start gap-2.5 rounded-xl border border-danger/30 bg-danger-soft p-3 text-sm text-danger">
          <AlertCircle className="mt-0.5 size-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      <Field label="6-digit code" htmlFor="totp-code">
        <Input
          id="totp-code"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={6}
          placeholder="123456"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          leftIcon={<KeyRound className="size-4" />}
          invalid={Boolean(error)}
          autoFocus
        />
      </Field>
      <Button type="submit" size="lg" className="w-full" loading={verifying} disabled={code.length !== 6}>
        {setup.kind === 'enroll' ? 'Turn on & continue' : 'Verify'}
      </Button>
    </form>
  );
}
