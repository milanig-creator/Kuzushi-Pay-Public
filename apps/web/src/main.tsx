import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { useTranslation } from "react-i18next";
import i18n from "./i18n";
import { api, ApiError } from "./api";
import { ProductWizard } from "./product-wizard";
import { StorefrontSetup } from "./storefront-setup";
import { StripeConnect } from "./stripe-connect";
import "./style.css";

type User = { id: string; email: string; role: "ADMIN" | "USER" };
type Business = {
  id: string; name: string; sandboxOAuthAvailable?: boolean;
  sandboxOAuthStatus?: "available" | "connected" | "unavailable";
  connectOnboardingAvailable?: boolean;
  liveOAuthStatus?: "available" | "connected" | "reconnect_required" | "unavailable";
};
type MfaState = "setup" | "challenge" | "recovery";
function App() {
  const { t } = useTranslation();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [businesses, setBusinesses] = useState<Business[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [selectedBusiness, setSelectedBusiness] = useState<Business | null>(null);
  const [wizardDirty, setWizardDirty] = useState(false);
  const [wizardBusy, setWizardBusy] = useState(false);
  const [recoveryAvailable, setRecoveryAvailable] = useState(false);
  const [mfaAvailable, setMfaAvailable] = useState(false);
  const [requestRecovery, setRequestRecovery] = useState(false);
  const [mfa, setMfa] = useState<MfaState | null>(null);
  const [mfaSecret, setMfaSecret] = useState<string | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [issuedRecoveryCode, setIssuedRecoveryCode] = useState<string | null>(null);
  const [resetToken, setResetToken] = useState(() => {
    const values = new URLSearchParams(window.location.hash.slice(1)).getAll("reset");
    if (values.length === 0) return null;
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    return values.length === 1 ? values[0] : "";
  });
  const currentUserId = useRef<string | null>(null);
  currentUserId.current = user?.id ?? null;

  function showError(err: unknown) {
    const codes: Record<string, string> = {
      INVALID_CREDENTIALS: "errorCredentials", CURRENT_PASSWORD_INVALID: "errorCurrentPassword",
      PASSWORD_UNCHANGED: "errorPasswordUnchanged", CREDENTIALS_CHANGED: "errorCredentialsChanged",
      INVALID_INPUT: "errorInput", INVALID_RESET: "errorInvalidReset",
      INVALID_MFA: "errorMfa", MFA_UNAVAILABLE: "errorMfaUnavailable",
      INVALID_RECOVERY_CODE: "errorMfaRecoveryCode", INVALID_RECOVERY_TARGET: "errorMfaRecoveryTarget",
      MFA_RECOVERY_REQUIRED: "errorMfaRecoveryCode",
      EMAIL_IN_USE: "errorEmail", RATE_LIMITED: "errorRate", PASSWORD_CAPACITY: "errorPasswordCapacity", UNAUTHENTICATED: "errorAuth",
      AUTHORIZATION_IN_PROGRESS: "errorOAuthInProgress",
      STRIPE_CONNECTION_UNAVAILABLE: "stripeSandboxUnavailable"
    };
    setError(codes[err instanceof ApiError ? err.message : ""] ?? "errorGeneric");
    if (err instanceof ApiError && ["UNAUTHENTICATED", "CREDENTIALS_CHANGED"].includes(err.message)) {
      currentUserId.current = null;
      setUser(null); setBusinesses([]); setSelectedBusiness(null); setWizardDirty(false); setWizardBusy(false);
      setMfa(null); setMfaSecret(null); setBackupCodes(null);
    }
  }
  async function loadBusinesses() {
    const userId = currentUserId.current;
    const result = await api<{ businesses: Business[]; connectOnboardingAvailable?: boolean }>("/api/businesses");
    if (userId && currentUserId.current === userId) setBusinesses(result.businesses.map((business) => ({
      ...business, connectOnboardingAvailable: result.connectOnboardingAvailable
    })));
  }
  useEffect(() => {
    void (async () => {
      try {
        const { user: current } = await api<{ user: User }>("/api/me");
        setUser(current);
      } catch (err) {
        if (err instanceof ApiError && err.message === "UNAUTHENTICATED") {
          try {
            const result = await api<{ mfa: MfaState | null }>("/api/mfa/status");
            setMfa(result.mfa);
          } catch (statusError) { showError(statusError); }
        } else showError(err);
      } finally { setLoading(false); }
    })();
    api<{ passwordRecovery: boolean; mfa: boolean }>("/api/features")
      .then(({ passwordRecovery, mfa: available }) => { setRecoveryAvailable(passwordRecovery); setMfaAvailable(available); })
      .catch(showError);
  }, []);
  useEffect(() => { if (user && !backupCodes) void loadBusinesses().catch(showError); }, [user, backupCodes]);
  useEffect(() => {
    const url = new URL(window.location.href);
    const result = url.searchParams.get("stripe_oauth");
    const messages: Record<string, string> = {
      identity_verified: "oauthIdentityVerified",
      connected: "stripeSandboxConnected",
      validated: "oauthStateValidated",
      failed: "oauthFailed",
      live_connected: "stripeExistingConnected",
      live_failed: "stripeExistingFailed"
    };
    if (result && messages[result]) {
      setNotice(messages[result]);
      url.searchParams.delete("stripe_oauth");
    }
    if (url.searchParams.has("session_id")) {
      setNotice("liveCheckoutReturned");
      url.searchParams.delete("session_id");
    }
    if (url.href !== window.location.href) {
      window.history.replaceState(null, "", url.pathname + url.search + url.hash);
    }
  }, []);
  useEffect(() => { document.documentElement.lang = i18n.language; }, [i18n.language]);
  useEffect(() => {
    if (!backupCodes && !issuedRecoveryCode) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [backupCodes, issuedRecoveryCode]);

  async function submit(event: React.FormEvent<HTMLFormElement>, action: "login" | "business" | "password" | "recovery" | "reset") {
    event.preventDefault();
    if (action === "password" && wizardDirty && !window.confirm(t("discardDraftChanges"))) return;
    const form = event.currentTarget;
    const data = Object.fromEntries(new FormData(form));
    setError(""); setNotice(""); setBusy(true);
    try {
      if (action === "login") {
        const result = await api<{ user: User } | { mfa: MfaState }>("/api/login", data);
        if ("user" in result) setUser(result.user);
        else { setMfa(result.mfa); setMfaSecret(null); }
      } else if (action === "business") {
        await api("/api/businesses", data);
        form.reset();
        await loadBusinesses();
        setNotice("created");
      } else if (action === "password") {
        await api("/api/password", data);
        form.reset();
        currentUserId.current = null;
        setUser(null); setBusinesses([]); setSelectedBusiness(null); setWizardDirty(false);
        setNotice("passwordChangedSignIn");
      } else if (action === "recovery") {
        await api("/api/password-reset/request", { ...data, language: i18n.language === "es" ? "es" : "en" });
        form.reset();
        setRequestRecovery(false);
        setNotice("recoveryRequested");
      } else {
        await api("/api/password-reset/confirm", { ...data, token: resetToken });
        form.reset();
        setResetToken(null); setUser(null); setBusinesses([]); setSelectedBusiness(null); setWizardDirty(false);
        setMfa(null); setMfaSecret(null);
        currentUserId.current = null;
        setNotice("passwordChangedSignIn");
      }
    } catch (err) { showError(err); }
    finally { setBusy(false); }
  }
  async function logout() {
    if (wizardDirty && !window.confirm(t("discardDraftChanges"))) return;
    if (backupCodes && !window.confirm(t("discardBackupCodes"))) return;
    if (issuedRecoveryCode && !window.confirm(t("discardMfaRecoveryCode"))) return;
    setError("");
    try {
      await api("/api/logout", {});
      currentUserId.current = null;
      setUser(null); setBusinesses([]); setSelectedBusiness(null); setWizardDirty(false);
      setMfa(null); setMfaSecret(null); setBackupCodes(null); setIssuedRecoveryCode(null);
    }
    catch (err) { showError(err); }
  }
  async function prepareMfa() {
    setError(""); setNotice(""); setBusy(true);
    try {
      const result = await api<{ secret: string }>("/api/mfa/setup", {});
      setMfaSecret(result.secret);
    } catch (err) {
      if (err instanceof ApiError && err.message === "MFA_ALREADY_ENROLLED") {
        setMfa("challenge"); setMfaSecret(null); setNotice("mfaAlreadyEnrolled");
      } else showError(err);
    } finally { setBusy(false); }
  }
  async function submitMfa(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.currentTarget));
    setError(""); setNotice(""); setBusy(true);
    try {
      if (mfa === "recovery") {
        await api("/api/mfa/recovery", data);
        setMfa("setup"); setMfaSecret(null);
        return;
      } else if (mfa === "setup") {
        const result = await api<{ user: User; backupCodes: string[] }>("/api/mfa/confirm", data);
        setBackupCodes(result.backupCodes); setUser(result.user);
      } else {
        const result = await api<{ user: User }>("/api/mfa/verify", data);
        setUser(result.user);
      }
      setMfa(null); setMfaSecret(null);
    } catch (err) { showError(err); }
    finally { setBusy(false); }
  }
  async function issueMfaRecovery(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (wizardDirty && !window.confirm(t("discardDraftChanges"))) return;
    if (!window.confirm(t("mfaRecoveryConfirm"))) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    setError(""); setNotice(""); setBusy(true);
    try {
      const result = await api<{ recoveryCode: string }>("/api/admin/mfa-recovery", {
        email: data.get("email"), code: data.get("code"), identityVerified: data.get("identityVerified") === "on"
      });
      form.reset();
      setSelectedBusiness(null); setWizardDirty(false); setIssuedRecoveryCode(result.recoveryCode);
    } catch (err) { showError(err); }
    finally { setBusy(false); }
  }
  async function replaceBackupCodes(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (wizardDirty && !window.confirm(t("discardDraftChanges"))) return;
    if (!window.confirm(t("mfaReplaceConfirm"))) return;
    const data = Object.fromEntries(new FormData(event.currentTarget));
    setError(""); setNotice(""); setBusy(true);
    try {
      const result = await api<{ backupCodes: string[] }>("/api/mfa/backup-codes", data);
      setSelectedBusiness(null); setWizardDirty(false); setBackupCodes(result.backupCodes);
    } catch (err) { showError(err); }
    finally { setBusy(false); }
  }
  async function connectStripe(businessId: string, mode: "live" | "sandbox") {
    setError(""); setNotice(""); setBusy(true);
    try {
      const result = await api<{ authorizationUrl: string }>(`/api/businesses/${businessId}/stripe/oauth/${mode}`, {});
      window.location.assign(result.authorizationUrl);
    } catch (err) { showError(err); setBusy(false); }
  }

  return <div className="shell">
    <header className="topbar">
      <a className="wordmark" href="/"><img className="mark" src="/brand-mark.png" alt="" width="40" height="40" /><span>Kuzushi <em>Pay</em></span></a>
      <div className="header-actions">
        <label className="language">{t("language")} <select value={i18n.language} onChange={(e) => void i18n.changeLanguage(e.target.value)}><option value="en">English</option><option value="es">Español</option></select></label>
        {user && <button className="button-outline" disabled={busy || wizardBusy} onClick={() => void logout()}>{t("signOut")}</button>}
      </div>
    </header>
    <main>
      {loading ? <p>{t("loading")}</p> : issuedRecoveryCode && resetToken === null ? <section className="panel">
        <h2>{t("mfaRecoveryIssuedTitle")}</h2><p>{t("mfaRecoveryIssuedInstructions")}</p>
        <p><code>{issuedRecoveryCode}</code></p>
        <button type="button" className="button-primary" onClick={() => setIssuedRecoveryCode(null)}>{t("mfaRecoveryCodeDelivered")}</button>
      </section> : backupCodes && resetToken === null ? <section className="panel">
        <h2>{t("mfaBackupTitle")}</h2><p>{t("mfaBackupInstructions")}</p>
        <ul>{backupCodes.map((code) => <li key={code}><code>{code}</code></li>)}</ul>
        <button type="button" className="button-primary" onClick={() => setBackupCodes(null)}>{t("mfaBackupSaved")}</button>
      </section> : !user || resetToken !== null ? <section className="login-layout">
        <div><p className="eyebrow">{t("studio")}</p><h1>{t("signInTitle")}</h1><p className="lead">{t("signInIntro")}</p><div className="gold-line" /></div>
        {mfa && resetToken === null && !requestRecovery ? <form className="panel" onSubmit={(e) => void submitMfa(e)}>
          <h2>{t(mfa === "setup" ? "mfaSetupTitle" : mfa === "recovery" ? "mfaRecoveryEnterTitle" : "mfaChallengeTitle")}</h2>
          {error && <p role="alert" className="error">{t(error)}</p>}
          {notice && <p role="status" className="notice">{t(notice)}</p>}
          {mfa === "setup" && !mfaSecret && <>
            <p>{t("mfaSetupIntro")}</p>
            <button type="button" className="button-primary" disabled={busy} onClick={() => void prepareMfa()}>{t("mfaGetKey")}</button>
          </>}
          {mfa === "setup" && mfaSecret && <><p>{t("mfaManualKey")}</p><p><code>{mfaSecret}</code></p></>}
          {mfa === "recovery" && <p>{t("mfaRecoveryEnterIntro")}</p>}
          {(mfa === "challenge" || mfa === "recovery" || mfaSecret) && <>
            <label>{t(mfa === "setup" ? "mfaCode" : mfa === "recovery" ? "mfaRecoveryCode" : "mfaCodeOrBackup")}
              <input name="code" autoComplete="one-time-code" required maxLength={mfa === "recovery" ? 64 : 35} /></label>
            <button className="button-primary" disabled={busy}>{t("mfaVerify")}</button>
          </>}
          <button type="button" className="button-outline" disabled={busy} onClick={() => void logout()}>{t("backToSignIn")}</button>
        </form> : <form className="panel" onSubmit={(e) => void submit(e, resetToken !== null ? "reset" : requestRecovery ? "recovery" : "login")}>
          <h2>{t(resetToken !== null ? "resetPassword" : requestRecovery ? "recoverPassword" : "signIn")}</h2>
          {error && <p role="alert" className="error">{t(error)}</p>}
          {notice && <p role="status" className="notice">{t(notice)}</p>}
          {resetToken === null && <label>{t("email")}<input name="email" type="email" autoComplete="username" required maxLength={254} /></label>}
          {resetToken !== null
            ? <label>{t("newPassword")}<input name="newPassword" type="password" autoComplete="new-password" required minLength={12} maxLength={128} /></label>
            : !requestRecovery && <label>{t("password")}<input name="password" type="password" autoComplete="current-password" required maxLength={128} /></label>}
          <button className="button-primary" disabled={busy}>{t(resetToken !== null ? "resetPassword" : requestRecovery ? "sendRecovery" : "signIn")}</button>
          {(requestRecovery || resetToken !== null) && <button className="button-outline" type="button" disabled={busy} onClick={() => {
            setResetToken(null); setRequestRecovery(false); setError(""); setNotice("");
          }}>{t("backToSignIn")}</button>}
          {recoveryAvailable && !requestRecovery && resetToken === null && <button className="button-outline" type="button" disabled={busy} onClick={() => {
            setRequestRecovery(true); setError(""); setNotice("");
          }}>{t("forgotPassword")}</button>}
        </form>}
      </section> : <section>
        <p className="eyebrow">{t("studio")} / {t("overview")}</p>
        <h1>{t("welcome")}</h1><p className="lead">{t("dashboardIntro")}</p>
        {error && <p role="alert" className="error">{t(error)}</p>}
        {notice && <p role="status" className="notice">{t(notice)}</p>}
        <div className="dashboard-grid">
          <div className="panel">
            <p className="eyebrow">01 / {t("overview")}</p><h2>{t("businesses")}</h2><p>{t("businessesIntro")}</p>
            {businesses.length === 0 ? <p className="empty">{t("empty")}</p> : <ul>{businesses.map((business) => <li className="business" key={business.id}>
              <strong>{business.name}</strong>
              {(business.liveOAuthStatus === "available" || business.liveOAuthStatus === "reconnect_required") &&
                <button className="button-outline" disabled={busy || wizardBusy}
                onClick={() => {
                  if (!wizardDirty || window.confirm(t("discardDraftChanges"))) void connectStripe(business.id, "live");
                }}>{t(business.liveOAuthStatus === "reconnect_required" ? "stripeExistingReconnect" : "stripeExistingConnect")}</button>}
              {business.liveOAuthStatus === "connected" && <span>{t("stripeExistingConnected")}</span>}
              {business.liveOAuthStatus === "unavailable" && !business.connectOnboardingAvailable && <span>{t("stripeSandboxUnavailable")}</span>}
              {business.connectOnboardingAvailable ? <StripeConnect businessId={business.id} disabled={busy || wizardBusy}
                onError={showError} canLeave={() => !wizardDirty || window.confirm(t("discardDraftChanges"))} />
                : business.sandboxOAuthStatus === "connected" ? <span>{t("stripeSandboxConnected")}</span>
                : business.sandboxOAuthStatus === "unavailable" ? <span>{t("stripeSandboxUnavailable")}</span>
                : business.sandboxOAuthAvailable && business.sandboxOAuthStatus === "available"
                  ? <button className="button-outline" disabled={busy || wizardBusy}
                      onClick={() => void connectStripe(business.id, "sandbox")}>{t("stripeSandboxConnect")}</button>
                : business.sandboxOAuthAvailable
                ? <><span>{t("sandboxOnly")}</span><button className="button-outline" disabled={busy || wizardBusy} onClick={() => void connectStripe(business.id, "sandbox")}>{t("connectStripeSandbox")}</button></>
                : !business.liveOAuthStatus && <span>{t("connection")}: {t("comingSoon")}</span>}
              <button className="button-outline" disabled={wizardBusy} onClick={() => {
                if (selectedBusiness?.id !== business.id && wizardDirty && !window.confirm(t("discardDraftChanges"))) return;
                if (selectedBusiness?.id !== business.id) setWizardDirty(false);
                setSelectedBusiness(business);
              }}>{t("manageProducts")}</button>
              <StorefrontSetup businessId={business.id} canApprove={user.role === "ADMIN"} onAuthError={showError} />
            </li>)}</ul>}
          </div>
          {user.role === "ADMIN" && <form className="panel" onSubmit={(e) => void submit(e, "business")}>
            <p className="eyebrow">02 / {t("overview")}</p><h2>{t("addBusiness")}</h2><p>{t("addIntro")}</p>
            <label>{t("businessName")}<input name="name" required maxLength={120} /></label>
            <label>{t("ownerEmail")}<input name="email" type="email" required maxLength={254} /></label>
            <label>{t("ownerPassword")}<input name="password" type="password" autoComplete="new-password" required minLength={12} maxLength={128} aria-describedby="password-hint" /></label>
            <small id="password-hint">{t("passwordHint")}</small>
            <button className="button-primary" disabled={busy}>{t("create")}</button>
          </form>}
          <form className="panel" onSubmit={(e) => void submit(e, "password")}>
            <p className="eyebrow">03 / {t("overview")}</p><h2>{t("changePassword")}</h2>
            <label>{t("currentPassword")}<input name="currentPassword" type="password" autoComplete="current-password" required maxLength={128} /></label>
            <label>{t("newPassword")}<input name="newPassword" type="password" autoComplete="new-password" required minLength={12} maxLength={128} /></label>
            <small>{t("changePasswordHint")}</small>
            <button className="button-primary" disabled={busy || wizardBusy}>{t("changePassword")}</button>
          </form>
          {mfaAvailable && <form className="panel" onSubmit={(e) => void replaceBackupCodes(e)}>
            <h2>{t("mfaReplaceTitle")}</h2><p>{t("mfaReplaceIntro")}</p>
            <label>{t("mfaCodeOrBackup")}<input name="code" autoComplete="one-time-code" required maxLength={35} /></label>
            <button className="button-primary" disabled={busy || wizardBusy}>{t("mfaReplaceTitle")}</button>
          </form>}
          {mfaAvailable && user.role === "ADMIN" && <form className="panel" onSubmit={(e) => void issueMfaRecovery(e)}>
            <h2>{t("mfaRecoveryAdminTitle")}</h2><p>{t("mfaRecoveryAdminIntro")}</p>
            <label>{t("email")}<input name="email" type="email" required maxLength={254} /></label>
            <label>{t("mfaCodeOrBackup")}<input name="code" autoComplete="one-time-code" required maxLength={35} /></label>
            <label className="confirmation"><input name="identityVerified" type="checkbox" required /> {t("mfaRecoveryIdentityVerified")}</label>
            <button className="button-primary" disabled={busy || wizardBusy}>{t("mfaRecoveryIssue")}</button>
          </form>}
        </div>
        {selectedBusiness && <ProductWizard key={selectedBusiness.id} business={selectedBusiness}
          onError={showError} dirty={wizardDirty} onDirtyChange={setWizardDirty} onBusyChange={setWizardBusy} />}
      </section>}
    </main>
  </div>;
}

createRoot(document.getElementById("root")!).render(<App />);
