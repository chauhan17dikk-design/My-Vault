import { Navigate, useLocation, useNavigate } from 'react-router';
import { toast } from 'sonner';
import { AuthLayout } from '@/layouts/AuthLayout';
import { FullPageLoader } from '@/components/layout/FullPageLoader';
import { TwoFactorForm } from '@/components/auth/TwoFactorForm';
import { useAuth } from '@/context/AuthContext';
import { getErrorMessage } from '@/lib/errors';

function safeFrom(state: unknown): string {
  const from = (state as { from?: string } | null)?.from;
  return from && from.startsWith('/') && !from.startsWith('//') ? from : '/';
}

/** Second sign-in step: the vault opens only for an aal2 session. */
export function TwoFactorPage() {
  const { session, aal, loading, signOut } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  if (loading) return <FullPageLoader />;
  if (!session) return <Navigate to="/login" replace />;
  if (aal === 'aal2') return <Navigate to={safeFrom(location.state)} replace />;

  return (
    <AuthLayout redirectIfSignedIn={false}>
      <div className="mb-6">
        <h2 className="text-2xl font-bold tracking-tight text-ink">Two-step verification</h2>
        <p className="mt-1.5 text-sm text-muted">Enter the code from your authenticator app to open your vault.</p>
      </div>
      <TwoFactorForm onVerified={() => navigate(safeFrom(location.state), { replace: true })} />
      <button
        type="button"
        onClick={() => signOut().catch((e) => toast.error(getErrorMessage(e)))}
        className="mt-6 w-full text-center text-sm font-medium text-muted hover:text-ink"
      >
        Cancel and sign out
      </button>
    </AuthLayout>
  );
}
