import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { apiFetch } from '../api';

export const emptyHveForm = () => ({
  tenant_id: '',
  client_id: '',
  credential: 'public',
  client_secret: '',
  certificate_pem: '',
  private_key_pem: '',
  oauth_mode: 'delegated',
});

// The form calls the credential "credential". The API field is oauth_credential.
export function hvePayload(form) {
  return {
    tenant_id: form.tenant_id,
    client_id: form.client_id,
    oauth_credential: form.credential,
    oauth_mode: form.oauth_mode,
    client_secret: form.client_secret,
    certificate_pem: form.certificate_pem,
    private_key_pem: form.private_key_pem,
  };
}

export async function readError(res) {
  const data = await res.json().catch(() => ({}));
  if (typeof data.detail === 'string') return data.detail;
  if (Array.isArray(data.detail)) {
    return data.detail.map(item => item.msg || JSON.stringify(item)).join(', ');
  }
  return data.error || `Error ${res.status}`;
}

function useServerConfig(serverConfig) {
  const [cfg, setCfg] = useState(serverConfig || null);
  useEffect(() => {
    if (serverConfig) {
      setCfg(serverConfig);
      return;
    }
    let cancelled = false;
    apiFetch('/api/providers/hve/config')
      .then(r => r.json())
      .then(data => { if (!cancelled) setCfg(data); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [serverConfig]);
  return cfg;
}

export default function HveFields({ value, onChange, serverConfig, prefill = true, keepHint = false }) {
  const { t } = useTranslation();
  const cfg = useServerConfig(serverConfig);
  const didPrefill = useRef(false);

  useEffect(() => {
    if (!prefill || !cfg || didPrefill.current) return;
    didPrefill.current = true;
    onChange(current => ({
      ...current,
      tenant_id: current.tenant_id || cfg.tenant_id || '',
      client_id: current.client_id || cfg.client_id || '',
      credential: current.credential === 'public' && cfg.credential ? cfg.credential : current.credential,
    }));
  }, [cfg, prefill, onChange]);

  const set = (patch) => onChange({ ...value, ...patch });

  return (
    <div>
      <div className="alert alert-warning" style={{ marginBottom: 12 }}>
        {t('providers.hve.intro')}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div className="form-group">
          <label className="form-label">{t('providers.hve.tenant')}</label>
          <input
            className="form-input"
            value={value.tenant_id}
            autoComplete="off"
            spellCheck={false}
            onChange={e => set({ tenant_id: e.target.value.trim() })}
          />
        </div>
        <div className="form-group">
          <label className="form-label">{t('providers.hve.client')}</label>
          <input
            className="form-input"
            value={value.client_id}
            autoComplete="off"
            spellCheck={false}
            onChange={e => set({ client_id: e.target.value.trim() })}
          />
        </div>
      </div>

      <div className="form-group">
        <label className="form-label">{t('providers.hve.credential')}</label>
        <select
          className="form-input"
          value={value.credential}
          onChange={e => set({ credential: e.target.value })}
        >
          <option value="public">{t('providers.hve.credential_public')}</option>
          <option value="secret">{t('providers.hve.credential_secret')}</option>
          <option value="certificate">{t('providers.hve.credential_certificate')}</option>
        </select>
      </div>

      {value.credential === 'secret' && (
        <div className="form-group">
          <label className="form-label">{t('providers.hve.secret')}</label>
          {keepHint && <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>{t('providers.hve.secret_keep')}</div>}
          {!keepHint && cfg?.credential === 'secret' && !value.client_secret && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>{t('providers.hve.server_secret')}</div>
          )}
          <input
            className="form-input"
            type="password"
            value={value.client_secret}
            autoComplete="new-password"
            onChange={e => set({ client_secret: e.target.value })}
          />
        </div>
      )}

      {value.credential === 'certificate' && (
        <>
          {keepHint && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>{t('providers.hve.cert_keep')}</div>
          )}
          {!keepHint && cfg?.credential === 'certificate' && !value.certificate_pem && !value.private_key_pem && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>{t('providers.hve.server_cert')}</div>
          )}
          <div className="form-group">
            <label className="form-label">{t('providers.hve.cert')}</label>
            <input
              type="file"
              accept=".pem,.crt,.cer,.txt"
              onChange={async e => {
                const file = e.target.files && e.target.files[0];
                if (file) set({ certificate_pem: await file.text() });
              }}
            />
            <textarea
              className="form-input"
              rows={4}
              value={value.certificate_pem}
              spellCheck={false}
              style={{ fontFamily: 'monospace', fontSize: 12, marginTop: 6 }}
              onChange={e => set({ certificate_pem: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label className="form-label">{t('providers.hve.key')}</label>
            <input
              type="file"
              accept=".pem,.key,.txt"
              onChange={async e => {
                const file = e.target.files && e.target.files[0];
                if (file) set({ private_key_pem: await file.text() });
              }}
            />
            <textarea
              className="form-input"
              rows={4}
              value={value.private_key_pem}
              spellCheck={false}
              style={{ fontFamily: 'monospace', fontSize: 12, marginTop: 6 }}
              onChange={e => set({ private_key_pem: e.target.value })}
            />
          </div>
        </>
      )}

      <div className="form-group">
        <label className="form-label">{t('providers.hve.mode')}</label>
        <select
          className="form-input"
          value={value.oauth_mode}
          onChange={e => set({ oauth_mode: e.target.value })}
        >
          <option value="delegated">{t('providers.hve.mode_delegated')}</option>
          <option value="application">{t('providers.hve.mode_application')}</option>
        </select>
        {value.oauth_mode === 'application' && (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
            {t('providers.hve.mode_application_hint')}
          </div>
        )}
      </div>

      {value.oauth_mode !== 'application' && cfg?.redirect_uri && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
          <div>{t('providers.hve.redirect_uri')}</div>
          <code style={{ wordBreak: 'break-all' }}>{cfg.redirect_uri}</code>
        </div>
      )}
      {value.oauth_mode !== 'application' && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
          {t('providers.hve.public_client_hint')}
        </div>
      )}
    </div>
  );
}

export function HveSignIn({ provider, onChanged, beforeSignIn }) {
  const { t } = useTranslation();
  const [pending, setPending] = useState(null);
  const [error, setError] = useState('');
  const [waiting, setWaiting] = useState(false);
  const [copied, setCopied] = useState(false);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState(() => ({
    ...emptyHveForm(),
    tenant_id: provider.oauth_tenant_id || '',
    client_id: provider.oauth_client_id || '',
    credential: provider.oauth_credential || 'public',
    oauth_mode: provider.oauth_mode || 'delegated',
  }));
  const poller = useRef(null);

  const stop = () => {
    if (poller.current) {
      clearTimeout(poller.current);
      poller.current = null;
    }
  };

  const schedule = (seconds) => {
    stop();
    poller.current = setTimeout(async () => {
      try {
        const res = await apiFetch(`/api/providers/${provider.id}/hve/device`);
        const data = await res.json();
        if (data.status === 'signed_in') {
          setPending(null);
          setWaiting(false);
          onChanged(true);
          return;
        }
        if (data.status === 'error') {
          setWaiting(false);
          setError(data.error || t('providers.hve.error', { error: '' }));
          return;
        }
        if (data.user_code) setPending(data);
        schedule(data.interval || seconds || 5);
      } catch (err) {
        setWaiting(false);
        setError(String(err));
      }
    }, Math.max(seconds || 5, 5) * 1000);
  };

  useEffect(() => {
    if (provider.oauth_signed_in || provider.oauth_mode === 'application') return undefined;
    let cancelled = false;
    apiFetch(`/api/providers/${provider.id}/hve/device`)
      .then(r => r.json())
      .then(data => {
        if (cancelled || data.status !== 'pending') return;
        setPending(data);
        setWaiting(true);
        schedule(data.interval || 5);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
      stop();
    };
    // Restore an in-progress code when the card mounts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider.id]);

  const prepare = async () => {
    if (!beforeSignIn) return true;
    try {
      return await beforeSignIn();
    } catch (err) {
      setError(String(err));
      return false;
    }
  };

  const startDevice = async () => {
    setError('');
    if (!(await prepare())) return;
    setWaiting(true);
    const res = await apiFetch(`/api/providers/${provider.id}/hve/device`, { method: 'POST', body: {} });
    if (!res.ok) {
      setWaiting(false);
      setError(await readError(res));
      return;
    }
    const data = await res.json();
    setPending(data);
    schedule(data.interval || 5);
  };

  const startBrowser = async () => {
    setError('');
    if (!(await prepare())) return;
    const res = await apiFetch(`/api/providers/${provider.id}/hve/redirect`, { method: 'POST', body: {} });
    if (!res.ok) {
      setError(await readError(res));
      return;
    }
    const data = await res.json();
    window.location.href = data.authorize_url;
  };

  const signOut = async () => {
    if (!confirm(t('providers.hve.signout_confirm'))) return;
    const res = await apiFetch(`/api/providers/${provider.id}/hve/sign-out`, { method: 'POST', body: {} });
    if (!res.ok) {
      setError(await readError(res));
      return;
    }
    setPending(null);
    stop();
    onChanged(false);
  };

  const saveEdit = async () => {
    setSaving(true);
    setError('');
    const res = await apiFetch(`/api/providers/${provider.id}/hve`, { method: 'PATCH', body: hvePayload(form) });
    setSaving(false);
    if (!res.ok) {
      setError(await readError(res));
      return;
    }
    const updated = await res.json();
    stop();
    setPending(null);
    setWaiting(false);
    setEditing(false);
    onChanged(!!updated.oauth_signed_in);
  };

  const copyCode = async () => {
    if (!pending?.user_code) return;
    try {
      await navigator.clipboard.writeText(pending.user_code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  const kind = provider.oauth_credential === 'certificate'
    ? t('providers.hve.kind_certificate')
    : provider.oauth_credential === 'secret'
      ? t('providers.hve.kind_secret')
      : t('providers.hve.kind_public');

  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 8 }}>
        {t('providers.hve.internal_only')}
        {' '}
        {t('providers.hve.credential_on_file', { kind })}
      </div>

      {provider.oauth_mode === 'application' && (
        <div className="alert alert-success" style={{ marginBottom: 8 }}>{t('providers.hve.app_mode')}</div>
      )}
      {provider.oauth_mode !== 'application' && provider.oauth_signed_in && (
        <div className="alert alert-success" style={{ marginBottom: 8 }}>{t('providers.hve.signed_in')}</div>
      )}
      {provider.oauth_mode !== 'application' && !provider.oauth_signed_in && !pending && (
        <div className="alert alert-warning" style={{ marginBottom: 8 }}>{t('providers.hve.needs_signin')}</div>
      )}

      {pending && (
        <div className="info-box" style={{ marginBottom: 8 }}>
          <div style={{ marginBottom: 6 }}>{t('providers.hve.code_help', {
            url: pending.verification_uri,
            email: provider.email,
          })}</div>
          <div style={{ fontFamily: 'monospace', fontSize: 28, letterSpacing: 2, fontWeight: 700, margin: '8px 0' }}>
            {pending.user_code}
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <a href={pending.verification_uri} target="_blank" rel="noopener noreferrer">{t('providers.hve.open_page')}</a>
            <button type="button" className="btn btn-secondary btn-sm" onClick={copyCode}>
              {copied ? t('providers.hve.copied') : t('providers.hve.copy')}
            </button>
          </div>
          {waiting && <div style={{ marginTop: 8, fontSize: 13 }}>{t('providers.hve.waiting')}</div>}
        </div>
      )}

      {error && <div className="alert alert-error" style={{ marginBottom: 8 }}>{error}</div>}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {provider.oauth_mode !== 'application' && (
          <>
            <button type="button" className="btn btn-primary btn-sm" onClick={startDevice}>{t('providers.hve.signin_code')}</button>
            <button type="button" className="btn btn-secondary btn-sm" onClick={startBrowser}>{t('providers.hve.signin_browser')}</button>
            {provider.oauth_signed_in && (
              <button type="button" className="btn btn-secondary btn-sm" onClick={signOut}>{t('providers.hve.signout')}</button>
            )}
          </>
        )}
        <button type="button" className="btn btn-secondary btn-sm" onClick={() => setEditing(open => !open)}>
          {t('providers.hve.edit_app')}
        </button>
      </div>

      {editing && (
        <div style={{ marginTop: 12 }}>
          <HveFields value={form} onChange={setForm} prefill={false} keepHint />
          <button type="button" className="btn btn-primary btn-sm" onClick={saveEdit} disabled={saving}>
            {saving ? t('common.loading') : t('common.save')}
          </button>
        </div>
      )}
    </div>
  );
}
