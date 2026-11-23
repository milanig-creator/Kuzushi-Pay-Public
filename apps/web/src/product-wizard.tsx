import { useEffect, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "./api";
import { LiveCheckout } from "./live-checkout";

type Kind = "PHYSICAL" | "DIGITAL" | "SERVICE";
type Billing = "ONE_TIME" | "RECURRING";
type Interval = "DAY" | "WEEK" | "MONTH" | "YEAR";
type Draft = {
  id: string;
  name: string;
  description: string;
  kind: Kind;
  amountCents: number;
  billing: Billing;
  interval: Interval | null;
};

function amountInCents(value: string): number | null {
  if (!/^[0-9]{1,6}(?:\.[0-9]{1,2})?$/.test(value)) return null;
  const [whole, fraction = ""] = value.split(".");
  const cents = Number(whole) * 100 + Number(fraction.padEnd(2, "0"));
  return cents >= 1 && cents <= 99999999 ? cents : null;
}

export function ProductWizard({ business, onError, dirty, onDirtyChange, onBusyChange }: {
  business: { id: string; name: string; liveOAuthStatus?: string };
  onError: (error: unknown) => void;
  dirty: boolean;
  onDirtyChange: (dirty: boolean) => void;
  onBusyChange: (busy: boolean) => void;
}) {
  const { t } = useTranslation();
  const [drafts, setDrafts] = useState<Draft[]>([]);
  const [publishedDrafts, setPublishedDrafts] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [reload, setReload] = useState(0);
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(1);
  const [editing, setEditing] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [kind, setKind] = useState<Kind>("PHYSICAL");
  const [amount, setAmount] = useState("");
  const [billing, setBilling] = useState<Billing>("ONE_TIME");
  const [interval, setInterval] = useState<Interval>("MONTH");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const base = `/api/businesses/${encodeURIComponent(business.id)}/product-drafts`;

  useEffect(() => {
    let active = true;
    setLoading(true);
    setLoadFailed(false);
    api<{ drafts: Draft[]; publications?: { draftId: string; published: boolean }[] }>(base)
      .then((result) => {
        if (!active) return;
        setDrafts(result.drafts);
        setPublishedDrafts(result.publications?.filter((item) => item.published).map((item) => item.draftId) ?? []);
      })
      .catch((failure: unknown) => {
        if (active) {
          setLoadFailed(true);
          if (failure instanceof ApiError && failure.message === "UNAUTHENTICATED") onError(failure);
        }
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [base, reload]);

  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  function reset() {
    setEditing(null); setName(""); setDescription(""); setKind("PHYSICAL");
    setAmount(""); setBilling("ONE_TIME"); setInterval("MONTH"); setStep(1); setError("");
    onDirtyChange(false);
  }
  function edit(draft: Draft) {
    if (dirty && !window.confirm(t("discardDraftChanges"))) return;
    setEditing(draft.id); setName(draft.name); setDescription(draft.description); setKind(draft.kind);
    setAmount((draft.amountCents / 100).toFixed(2)); setBilling(draft.billing);
    setInterval(draft.interval ?? "MONTH"); setStep(1); setError(""); setNotice("");
    onDirtyChange(false);
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(""); setNotice("");
    if (step === 1) {
      if (!name.trim()) { setError("productNameRequired"); return; }
      setStep(2);
      return;
    }
    const cents = amountInCents(amount);
    if (cents === null) { setError("productAmountError"); return; }
    if (step === 2) { setStep(3); return; }
    setBusy(true);
    onBusyChange(true);
    try {
      const body = {
        name, description, kind, amountCents: cents, billing,
        interval: billing === "RECURRING" ? interval : null
      };
      const url = editing ? `${base}/${encodeURIComponent(editing)}` : base;
      const result = await api<{ draft: Draft }>(url, body, editing ? "PUT" : "POST");
      setDrafts((existing) => [result.draft, ...existing.filter((draft) => draft.id !== result.draft.id)]);
      reset();
      setNotice("draftSaved");
    } catch (failure) {
      setError("errorGeneric");
      if (failure instanceof ApiError && failure.message === "UNAUTHENTICATED") onError(failure);
    }
    finally { setBusy(false); onBusyChange(false); }
  }

  async function publish(draft: Draft) {
    if (busy || dirty || !window.confirm(t("publishLiveConfirm", { name: draft.name }))) return;
    setError(""); setNotice(""); setBusy(true); onBusyChange(true);
    try {
      await api(`${base}/${encodeURIComponent(draft.id)}/publish`, {});
      setPublishedDrafts((existing) => [...existing, draft.id]);
      setNotice("publishedLive");
    } catch (failure) {
      setError(failure instanceof ApiError && failure.message === "PUBLICATION_OUTCOME_UNCERTAIN"
        ? "publishLiveUncertain" : "publishLiveFailed");
      if (failure instanceof ApiError && failure.message === "UNAUTHENTICATED") onError(failure);
    } finally {
      setBusy(false); onBusyChange(false);
    }
  }

  return <section className="panel product-panel">
    <p className="eyebrow">{t("productWizard")} / {business.name}</p>
    <h2>{t("productDrafts")}</h2>
    <p>{t(business.liveOAuthStatus === "connected" ? "publishLiveIntro" : "draftOnlyNotice")}</p>
    {loading ? <p>{t("loading")}</p> : loadFailed ? <div>
      <p role="alert" className="error">{t("draftLoadFailed")}</p>
      <button type="button" className="button-outline" onClick={() => setReload(reload + 1)}>{t("retry")}</button>
    </div> : drafts.length === 0 ? <p>{t("noDrafts")}</p> :
      <ul>{drafts.map((draft) => <li className="business" key={draft.id}>
        <strong>{draft.name}</strong>
        <span>{t("draft")} · USD {(draft.amountCents / 100).toFixed(2)} · {t(draft.billing === "ONE_TIME" ? "oneTime" : "recurring")}</span>
        <button type="button" className="button-outline" disabled={busy} onClick={() => edit(draft)}>{t("editDraft")}</button>
        {publishedDrafts.includes(draft.id) ? <span>{t("publishedLive")}</span> :
          business.liveOAuthStatus === "connected" &&
          <button type="button" className="button-outline" disabled={busy || dirty}
            onClick={() => void publish(draft)}>{t("publishLive")}</button>}
      </li>)}</ul>}
    <form onSubmit={(event) => void submit(event)}>
      <fieldset disabled={busy || loading || loadFailed}>
      <h3>{editing ? t("editDraft") : t("newDraft")}</h3>
      <p>{t("wizardStep", { step })}</p>
      {step === 1 && <>
        <label>{t("productName")}<input value={name} onChange={(event) => { setName(event.target.value); onDirtyChange(true); }} required maxLength={120} /></label>
        <label>{t("productDescription")}<textarea value={description} onChange={(event) => { setDescription(event.target.value); onDirtyChange(true); }} maxLength={500} /></label>
        <label>{t("productKind")}<select value={kind} onChange={(event) => { setKind(event.target.value as Kind); onDirtyChange(true); }}>
          <option value="PHYSICAL">{t("physical")}</option><option value="DIGITAL">{t("digital")}</option><option value="SERVICE">{t("service")}</option>
        </select></label>
      </>}
      {step === 2 && <>
        <label>{t("priceUsd")}<input value={amount} onChange={(event) => { setAmount(event.target.value); onDirtyChange(true); }} inputMode="decimal" required aria-describedby="price-hint" /></label>
        <small id="price-hint">{t("priceHint")}</small>
        <label>{t("billingType")}<select value={billing} onChange={(event) => { setBilling(event.target.value as Billing); onDirtyChange(true); }}>
          <option value="ONE_TIME">{t("oneTime")}</option><option value="RECURRING">{t("recurring")}</option>
        </select></label>
        {billing === "RECURRING" && <label>{t("billingInterval")}<select value={interval} onChange={(event) => { setInterval(event.target.value as Interval); onDirtyChange(true); }}>
          <option value="DAY">{t("daily")}</option><option value="WEEK">{t("weekly")}</option>
          <option value="MONTH">{t("monthly")}</option><option value="YEAR">{t("yearly")}</option>
        </select></label>}
      </>}
      {step === 3 && <div>
        <p><strong>{name.trim()}</strong> · {t(kind === "PHYSICAL" ? "physical" : kind === "DIGITAL" ? "digital" : "service")}</p>
        {description.trim() && <p>{description.trim()}</p>}
        <p>USD {amount} · {t(billing === "ONE_TIME" ? "oneTime" : "recurring")}
          {billing === "RECURRING" && ` · ${t(interval === "DAY" ? "daily" : interval === "WEEK" ? "weekly" : interval === "MONTH" ? "monthly" : "yearly")}`}</p>
        <p>{t("draftLimitations")}</p>
      </div>}
      {error && <p role="alert" className="error">{t(error)}</p>}
      {notice && <p role="status" className="notice">{t(notice)}</p>}
      <div className="wizard-actions">
        {step > 1 && <button type="button" className="button-outline" disabled={busy} onClick={() => { setStep(step - 1); setError(""); }}>{t("back")}</button>}
        {editing && <button type="button" className="button-outline" disabled={busy} onClick={() => {
          if (!dirty || window.confirm(t("discardDraftChanges"))) reset();
        }}>{t("cancelEdit")}</button>}
        <button className="button-primary" disabled={busy}>{t(step === 3 ? "saveDraft" : "next")}</button>
      </div>
      </fieldset>
    </form>
    {business.liveOAuthStatus === "connected" &&
      <LiveCheckout businessId={business.id} products={drafts.filter((draft) => publishedDrafts.includes(draft.id))}
        onError={onError} />}
  </section>;
}
