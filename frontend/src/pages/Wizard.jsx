import { useTranslation } from 'react-i18next';
import { useState, useEffect } from 'react';
import { apiFetch } from '../api';
import LanguageSwitcher from '../components/LanguageSwitcher';
import HveFields, { HveSignIn, emptyHveForm, hvePayload, readError } from '../components/HveAuth';

// Providers that require app passwords
const APP_PASSWORD_PROVIDERS = ['gmail', 'outlook', 'yahoo'];

export default function Wizard({ onComplete }) {
  const { t, i18n } = useTranslation();
  const [step, setStep] = useState(1);
  const [email, setEmail] = useState('');
  const [detected, setDetected] = useState(null);
  const [detecting, setDetecting] = useState(false);
  const [providerType, setProviderType] = useState(null);
  const [credentials, setCredentials] = useState({ host: '', port: 587, user: '', password: '', tls: 'starttls' });
  const [dnsResults, setDnsResults] = useState(null);
  const [dnsLoading, setDnsLoading] = useState(false);
  const [smtpCreds, setSmtpCreds] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [testLoading, setTestLoading] = useState(false);
  const [providerId, setProviderId] = useState(null);
  const [relayInfo, setRelayInfo] = useState({ hostname: '', port: 2525 });
  const [hveChosen, setHveChosen] = useState(false);
  const [hveForm, setHveForm] = useState(emptyHveForm);
  const [hveSignedIn, setHveSignedIn] = useState(false);

  const hveFlow = providerType === 'microsoft_hve';
  const totalSteps = hveFlow ? 6 : 5;
  const dnsStep = hveFlow ? 4 : 3;
  const accessStep = hveFlow ? 5 : 4;

  // Load relay connection info
  useEffect(() => {
    apiFetch('/api/relay-info').then(r => r.json()).then(setRelayInfo).catch(() => {});
  }, []);

  // Run DNS check when entering the DNS step
  useEffect(() => {
    if (step === dnsStep && !dnsResults && !dnsLoading) {
      checkDns();
    }
  }, [step, dnsStep]);

  // Step 1: Detect provider from email
  const detectProvider = async (force = false) => {
    if (!email.includes('@')) return;
    if (!force && hveChosen) return;
    setDetecting(true);
    try {
      const res = await apiFetch('/api/providers/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await res.json();
      setDetected(data);
      if (data.preset) {
        setProviderType(data.provider_type);
        setCredentials({
          host: data.preset.smtp_host || '',
          port: data.preset.smtp_port || 587,
          user: email,
          password: '',
          tls: data.preset.tls_mode || 'starttls',
        });
      }
    } catch (e) {
      console.error(e);
    }
    setDetecting(false);
  };

  // Step 2: Save provider
  const saveProvider = async () => {
    const isHve = providerType === 'microsoft_hve';
    const authMethod = isHve ? 'oauth' : (APP_PASSWORD_PROVIDERS.includes(providerType) ? 'app_password' : 'plain');
    const res = await apiFetch('/api/providers/', {
      method: 'POST',
      body: {
        provider_type: providerType || 'custom',
        email,
        smtp_host: credentials.host,
        smtp_port: credentials.port,
        tls_mode: credentials.tls,
        auth_method: authMethod,
        username: credentials.user || email,
        password: isHve ? undefined : credentials.password,
        is_default: true,
        ...(isHve ? hvePayload(hveForm) : {}),
      },
    });
    if (res.ok) {
      const provider = await res.json();
      setProviderId(provider.id);
      setHveSignedIn(!!provider.oauth_signed_in);
      setTestResult(null);
      return provider;
    }
    setTestResult({ healthy: false, error: await readError(res) });
    return null;
  };

  // Save HVE app settings. Returns the provider, or null when the save failed.
  const persistHve = async () => {
    if (!providerId) return saveProvider();
    const res = await apiFetch(`/api/providers/${providerId}/hve`, {
      method: 'PATCH',
      body: hvePayload(hveForm),
    });
    if (!res.ok) {
      setTestResult({ healthy: false, error: await readError(res) });
      return null;
    }
    const updated = await res.json();
    setHveSignedIn(!!updated.oauth_signed_in);
    setTestResult(null);
    return updated;
  };

  // Step 2: Test connection (real SMTP AUTH)
  const testConnection = async () => {
    let id = providerId;
    if (providerType === 'microsoft_hve') {
      const saved = await persistHve();
      if (!saved) return;
      id = saved.id;
    } else if (!id) {
      const created = await saveProvider();
      if (!created) return;
      id = created.id;
    } else {
      // Provider already saved — update credentials before testing
      await apiFetch(`/api/providers/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          smtp_host: credentials.host,
          smtp_port: credentials.port,
          tls_mode: credentials.tls,
          username: credentials.user,
          password: credentials.password,
        }),
      });
    }
    setTestLoading(true);
    setTestResult(null);
    try {
      const res = await apiFetch(`/api/providers/${id}/test`, { method: 'POST' });
      const data = await res.json();
      setTestResult(data);
    } catch (e) {
      setTestResult({ healthy: false, error: String(e) });
    }
    setTestLoading(false);
  };

  // Step 3: Check DNS
  const checkDns = async () => {
    const domain = email.split('@')[1];
    if (!domain) return;
    setDnsLoading(true);
    try {
      const res = await apiFetch('/api/providers/dns-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, provider_type: providerType || 'custom' }),
      });
      setDnsResults(await res.json());
    } catch (e) {
      console.error(e);
    }
    setDnsLoading(false);
  };

  // Access step: one SMTP login. Any IP can connect with it.
  const saveClient = async () => {
    if (smtpCreds?.smtp_password_plain) return;
    const res = await apiFetch('/api/clients/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'App', client_type: 'smtp_auth', provider_id: providerId }),
    });
    const data = await res.json().catch(() => ({}));
    if (data.smtp_password_plain) setSmtpCreds(data);
  };

  // Step 5: Send test email
  const [testTo, setTestTo] = useState('');
  const [testStatus, setTestStatus] = useState(null);
  const [testSending, setTestSending] = useState(false);

  const sendTestEmail = async () => {
    if (!testTo) return;
    setTestSending(true);
    setTestStatus(null);
    try {
      const res = await apiFetch('/api/test-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ from: email, to: testTo }),
      });
      const data = await res.json();
      setTestStatus(data.success ? 'ok' : data.error || 'error');
    } catch (e) {
      setTestStatus(String(e));
    }
    setTestSending(false);
  };

  // Helper: get provider note in current language
  const getProviderNote = () => {
    if (!detected?.preset) return null;
    const lang = i18n.language?.substring(0, 2) || 'en';
    return detected.preset[`notes_${lang}`] || detected.preset.notes_en || null;
  };

  // Helper: check if current provider needs app password
  const needsAppPassword = APP_PASSWORD_PROVIDERS.includes(providerType);
  const appPasswordUrl = detected?.preset?.app_password_url || null;

  const chooseHve = (on) => {
    setHveChosen(on);
    if (!on) {
      setProviderType(null);
      detectProvider(true);
      return;
    }
    setProviderType('microsoft_hve');
    setDetected({
      provider_type: 'microsoft_hve',
      provider_name: 'Microsoft 365 High Volume Email',
      preset: { smtp_host: 'smtp.hve.mx.microsoft', smtp_port: 587, tls_mode: 'starttls' },
    });
    setCredentials(c => ({
      ...c,
      host: 'smtp.hve.mx.microsoft',
      port: 587,
      tls: 'starttls',
      user: email,
    }));
  };

  const testMailbox = async () => {
    if (!providerId) return;
    setTestLoading(true);
    setTestResult(null);
    try {
      const res = await apiFetch(`/api/providers/${providerId}/test`, { method: 'POST' });
      const data = await res.json();
      setTestResult(data);
      if (typeof data.oauth_signed_in === 'boolean') setHveSignedIn(data.oauth_signed_in);
    } catch (e) {
      setTestResult({ healthy: false, error: String(e) });
    }
    setTestLoading(false);
  };

  const nextStep = async () => {
    if (step === 2 && hveFlow) {
      const saved = await persistHve();
      if (!saved) return;
    } else if (step === 2 && !providerId) {
      const created = await saveProvider();
      if (!created) return;
    }
    if (hveFlow && step === 3 && hveForm.oauth_mode !== 'application') {
      const res = await apiFetch('/api/providers/');
      const rows = await res.json().catch(() => []);
      const row = Array.isArray(rows) ? rows.find(item => String(item.id) === String(providerId)) : null;
      if (!row?.oauth_signed_in) {
        setHveSignedIn(false);
        setTestResult({ healthy: false, error: t('providers.hve.needs_signin') });
        return;
      }
      setHveSignedIn(true);
    }
    if (step === accessStep) {
      await saveClient();
    }
    setStep(s => Math.min(s + 1, totalSteps));
  };

  return (
    <div className="wizard">
      <div className="wizard-header">
        <div style={{ marginBottom: 20 }}><LanguageSwitcher /></div>
        <div className="logo" style={{ justifyContent: 'center', marginBottom: 16 }}>
          <span className="logo-icon">⚡</span>
          <span className="logo-text" style={{ fontSize: 28 }}>{t('app.name')}</span>
        </div>
        <h1 className="wizard-title">{t('wizard.title')}</h1>
        <p className="wizard-subtitle">{t('app.tagline')}</p>
      </div>

      {/* Progress */}
      <div className="wizard-steps">
        {Array.from({ length: totalSteps }, (_, i) => (
          <div key={i} className={`wizard-step ${i + 1 === step ? 'active' : i + 1 < step ? 'done' : ''}`} />
        ))}
      </div>

      {/* Step 1: Email */}
      {step === 1 && (
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: 8 }}>{t('wizard.step1_title')}</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: 16, fontSize: 14 }}>{t('wizard.step1_desc')}</p>
          <div className="form-group">
            <input
              className="form-input"
              type="email"
              placeholder={t('wizard.step1_placeholder')}
              value={email}
              onChange={e => { setEmail(e.target.value); setDetected(null); }}
              onBlur={() => detectProvider(false)}
            />
          </div>
          {detecting && <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>{t('wizard.step1_detecting')}</p>}
          {detected && detected.provider_name && (
            <div className="alert alert-success">
              {t('wizard.step1_detected', { provider: detected.provider_name })}
            </div>
          )}
          {detected && !detected.provider_name && detected.preset && (
            <div className="alert alert-warning">
              {t('wizard.step1_guessed', { host: detected.preset.smtp_host })}
            </div>
          )}
          {detected && !detected.provider_name && !detected.preset && (
            <div className="alert alert-warning">{t('wizard.step1_not_detected')}</div>
          )}
          {email.includes('@') && (
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, fontSize: 14 }}>
              <input type="checkbox" checked={hveChosen} onChange={e => chooseHve(e.target.checked)} />
              {t('providers.hve.use')}
            </label>
          )}
        </div>
      )}

      {/* Step 2: Connect account */}
      {step === 2 && (
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: 8 }}>{hveFlow ? t('providers.hve.app_title') : t('wizard.step2_title')}</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: 16, fontSize: 14 }}>{hveFlow ? t('providers.hve.app_intro') : t('wizard.step2_desc')}</p>

          {/* App password info box */}
          {needsAppPassword && (
            <div className="alert alert-warning" style={{ marginBottom: 16 }}>
              <div style={{ marginBottom: 8 }}>{getProviderNote()}</div>
              {appPasswordUrl && (
                <a
                  href={appPasswordUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ fontWeight: 600 }}
                >
                  {t('wizard.step2_app_password_link')} →
                </a>
              )}
            </div>
          )}

          {!hveFlow && (
            <>
              <div className="form-group">
                <label className="form-label">{t('wizard.step2_manual_host')}</label>
                <input className="form-input" value={credentials.host} onChange={e => setCredentials({ ...credentials, host: e.target.value })} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div className="form-group">
                  <label className="form-label">{t('wizard.step2_manual_port')}</label>
                  <input className="form-input" type="number" value={credentials.port} onChange={e => setCredentials({ ...credentials, port: parseInt(e.target.value) })} />
                </div>
                <div className="form-group">
                  <label className="form-label">{t('wizard.step2_manual_tls')}</label>
                  <select className="form-input" value={credentials.tls} onChange={e => {
                    const tls = e.target.value;
                    const portMap = { starttls: 587, ssl: 465, none: 25 };
                    setCredentials({ ...credentials, tls, port: portMap[tls] || credentials.port });
                  }}>
                    <option value="starttls">{t('wizard.step2_tls_starttls')}</option>
                    <option value="ssl">{t('wizard.step2_tls_ssl')}</option>
                    <option value="none">{t('wizard.step2_tls_none')}</option>
                  </select>
                </div>
              </div>
            </>
          )}
          {providerType === 'microsoft_hve' ? (
            <HveFields value={hveForm} onChange={setHveForm} />
          ) : (
            <>
              <div className="form-group">
                <label className="form-label">{t('wizard.step2_manual_user')}</label>
                <input className="form-input" value={credentials.user} onChange={e => setCredentials({ ...credentials, user: e.target.value })} />
              </div>
              <div className="form-group">
                <label className="form-label">
                  {needsAppPassword ? t('wizard.step2_app_password_label') : t('wizard.step2_manual_password')}
                </label>
                <input className="form-input" type="password" value={credentials.password} onChange={e => setCredentials({ ...credentials, password: e.target.value })} />
              </div>
            </>
          )}
          {hveFlow && testResult && !testResult.healthy && (
            <div className="alert alert-error">{testResult.error}</div>
          )}
          {!hveFlow && testResult && (
            <div className={`alert ${testResult.healthy ? 'alert-success' : 'alert-error'}`}>
              {testResult.healthy ? t('wizard.step2_test_ok') : t('wizard.step2_test_fail', { error: testResult.error })}
            </div>
          )}
          {!hveFlow && (
            <button className="btn btn-secondary" onClick={testConnection} disabled={testLoading}>
              {testLoading ? t('common.loading') : t('wizard.step2_test')}
            </button>
          )}
        </div>
      )}

      {hveFlow && step === 3 && (
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: 8 }}>{t('providers.hve.signin_title')}</h2>
          {hveForm.oauth_mode === 'application' ? (
            <div className="alert alert-success">{t('providers.hve.app_mode')}</div>
          ) : (
            <>
              <p style={{ color: 'var(--text-muted)', marginBottom: 16, fontSize: 14 }}>{t('providers.hve.signin_intro', { email })}</p>
              {providerId && (
                <HveSignIn
                  provider={{
                    id: providerId,
                    email,
                    oauth_mode: hveForm.oauth_mode,
                    oauth_credential: 'certificate',
                    oauth_signed_in: hveSignedIn,
                    oauth_tenant_id: hveForm.tenant_id,
                    oauth_client_id: hveForm.client_id,
                  }}
                  showEdit={false}
                  onChanged={(signedIn) => setHveSignedIn(!!signedIn)}
                />
              )}
            </>
          )}
          {testResult && (
            <div className={`alert ${testResult.healthy ? 'alert-success' : 'alert-error'}`}>
              {testResult.healthy ? t('wizard.step2_test_ok') : t('wizard.step2_test_fail', { error: testResult.error })}
            </div>
          )}
          {(hveSignedIn || hveForm.oauth_mode === 'application') && (
            <button className="btn btn-secondary" onClick={testMailbox} disabled={testLoading}>
              {testLoading ? t('common.loading') : t('wizard.step2_test')}
            </button>
          )}
        </div>
      )}

      {/* DNS check */}
      {step === dnsStep && (
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: 8 }}>{t('wizard.step3_title')}</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: 16, fontSize: 14 }}>{t('wizard.step3_desc')}</p>

          {dnsLoading && <p style={{ color: 'var(--text-muted)' }}>{t('wizard.step3_checking')}</p>}
          {dnsResults && dnsResults.map((r, i) => (
            <div key={i} className="dns-result">
              <span className={r.status === 'ok' ? 'dns-ok' : 'dns-missing'}>
                {r.status === 'ok' ? '✓' : '⚠'}
              </span>
              <div>
                <strong>{t(`dns.${r.record_type}_record`)}</strong>
                <span style={{ marginLeft: 8 }} className={`badge ${r.status === 'ok' ? 'badge-success' : 'badge-warning'}`}>
                  {t(`dns.status_${r.status}`)}
                </span>
                {r.suggestion && <div className="dns-suggestion">{r.suggestion}</div>}
              </div>
            </div>
          ))}

          {!dnsLoading && dnsResults && (
            <button className="btn btn-secondary" onClick={checkDns} style={{ marginTop: 12 }}>
              {t('wizard.step3_recheck')}
            </button>
          )}
        </div>
      )}

      {/* Step 4: Security */}
      {step === accessStep && (
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: 8 }}>{t('wizard.step4_title')}</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: 16, fontSize: 14 }}>{t('wizard.step4_desc')}</p>

          <div className="alert alert-error" style={{ marginBottom: 16 }}>
            ⚠ {t('clients.access_required')}
          </div>

          {smtpCreds && (
            <div className="info-box">
              <div><span className="label">{t('wizard.step4_auth_username')}: </span><span className="value">{smtpCreds.smtp_username}</span></div>
              <div><span className="label">{t('wizard.step4_auth_password')}: </span><span className="value">{smtpCreds.smtp_password_plain}</span></div>
              <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>{t('clients.save_credentials')}</div>
            </div>
          )}
        </div>
      )}

      {/* Step 5: Done */}
      {step === totalSteps && (
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: 8 }}>{t('wizard.step5_title')}</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: 16, fontSize: 14 }}>{t('wizard.step5_desc')}</p>

          <div className="info-box" style={{ marginBottom: 20 }}>
            <div><span className="label">{t('wizard.step5_host')}: </span><span className="value">{relayInfo.hostname}</span></div>
            <div><span className="label">{t('wizard.step5_port')}: </span><span className="value">{relayInfo.port}</span></div>
            <div><span className="label">{t('wizard.step5_from')}: </span><span className="value">{email}</span></div>
            {smtpCreds && (
              <>
                <div><span className="label">{t('wizard.step4_auth_username')}: </span><span className="value">{smtpCreds.smtp_username}</span></div>
                <div><span className="label">{t('wizard.step4_auth_password')}: </span><span className="value">{smtpCreds.smtp_password_plain}</span></div>
              </>
            )}
          </div>

          <div style={{ marginBottom: 20 }}>
            <label className="form-label">{t('wizard.step5_test_to')}</label>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                className="form-input"
                type="email"
                placeholder="test@example.com"
                value={testTo}
                onChange={e => setTestTo(e.target.value)}
              />
              <button className="btn btn-primary" onClick={sendTestEmail} disabled={testSending || !testTo}>
                {testSending ? t('common.loading') : t('wizard.step5_test_send')}
              </button>
            </div>
            {testStatus === 'ok' && <div className="alert alert-success" style={{ marginTop: 8 }}>{t('wizard.step5_test_ok')}</div>}
            {testStatus && testStatus !== 'ok' && <div className="alert alert-error" style={{ marginTop: 8 }}>{t('wizard.step5_test_fail', { error: testStatus })}</div>}
          </div>

          <button className="btn btn-primary" onClick={onComplete}>{t('nav.dashboard')}</button>
        </div>
      )}

      {/* Navigation */}
      <div className="wizard-footer">
        {step > 1 ? (
          <button className="btn btn-secondary" onClick={() => setStep(s => s - 1)}>{t('common.back')}</button>
        ) : <div />}
        {step < totalSteps ? (
          <button
            className="btn btn-primary"
            onClick={nextStep}
            disabled={
              (step === 1 && !email) ||
              (hveFlow && step === 3 && hveForm.oauth_mode !== 'application' && !hveSignedIn)
            }
          >
            {t('common.next')}
          </button>
        ) : null}
      </div>
    </div>
  );
}
