export function PermissionDeniedState() {
  return (
    <div
      role="alert"
      aria-live="assertive"
      className="rounded-lg border border-yellow-300 bg-yellow-50 p-6 text-center"
    >
      <div aria-hidden="true" className="text-3xl mb-2">🔒</div>
      <h2 className="text-lg font-semibold text-yellow-900">Read-only access</h2>
      <p className="mt-2 text-sm text-yellow-800">
        Your current role does not permit editing the control catalogue. Contact
        a DevSecOps engineer or AppSec lead to request write access.
      </p>
      <p className="mt-1 text-xs text-yellow-700">
        Authorization is enforced server-side. This view will always show the
        current active catalogue without edit affordances.
      </p>
    </div>
  );
}
