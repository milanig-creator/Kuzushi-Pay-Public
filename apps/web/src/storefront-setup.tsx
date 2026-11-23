import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "./api";

type Proposal = {
  origin: string;
  returnUrl: string;
  revision: string;
  verifiedAt: string | null;
  testApprovedAt: string | null;
  challenge: { name: string; value: string } | null;
};
type StorefrontResponse = { proposal: Proposal | null; pilotConfigured?: boolean };
type PilotOrder = { id: string; createdAt: string; initialPaymentStatus: "PAID" | "UNPAID" };

const errorMessages: Record<string, string> = {
  INVALID_INPUT: "storefrontInvalid",
  RATE_LIMITED: "errorRate",
  STOREFRONT_DNS_UNVERIFIED: "storefrontDnsUnverified",
  STOREFRONT_APPROVAL_UNAVAILABLE: "storefrontApprovalUnavailable"
};

export function StorefrontSetup({ businessId, canApprove, onAuthError }: {
  businessId: string;
  canApprove: boolean;
  onAuthError: (error: unknown) => void;
}) {
  const { t, i18n } = useTranslation();
  const endpoint = `/api/businesses/${encodeURIComponent(businessId)}/storefront`;
  const [opened, setOpened] = useState(false);
  const [proposal, setProposal] = useState<Proposal | null>(null);
  const [origin, setOrigin] = useState("");
  const [returnUrl, setReturnUrl] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [pilotConfigured, setPilotConfigured] = useState(false);
  const [pilotOrders, setPilotOrders] = useState<PilotOrder[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  function accept(saved: Proposal | null) {
    setProposal(saved);
    setOrigin(saved?.origin ?? "");
    setReturnUrl(saved?.returnUrl ?? "");
    setLoaded(true);
  }
  function report(cause: unknown) {
    const code = cause instanceof ApiError ? cause.message : "";
    if (code === "UNAUTHENTICATED") onAuthError(cause);
    setError(errorMessages[code] ?? "errorGeneric");
  }
  async function run(operation: () => Promise<StorefrontResponse>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await operation();
      accept(result.proposal);
      if (result.pilotConfigured) setPilotConfigured(true);
    } catch (cause) {
      report(cause);
    } finally {
      setBusy(false);
    }
  }
  async function refreshPilotOrders() {
    setBusy(true);
    setError("");
    try {
      const { orders } = await api<{ orders: PilotOrder[] }>(`${endpoint}/pilot-orders`);
      setPilotOrders(orders);
    } catch (cause) {
      report(cause);
    } finally {
      setBusy(false);
    }
  }
  const dirty = origin.trim() !== (proposal?.origin ?? "") || returnUrl.trim() !== (proposal?.returnUrl ?? "");
  const challenge = proposal?.challenge;

  function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(() => api<StorefrontResponse>(endpoint, { origin: origin.trim(), returnUrl: returnUrl.trim() }, "PUT"));
  }

  async function copy(value: string) {
    setNotice("");
    try {
      await navigator.clipboard.writeText(value);
      setNotice("storefrontCopied");
    } catch {
      setNotice("storefrontCopyManually");
    }
  }

  return <details className="storefront-setup" onToggle={(event) => {
    if (event.currentTarget.open && !opened) {
      setOpened(true);
      void run(() => api<StorefrontResponse>(endpoint));
    }
  }}>
    <summary>{t("storefrontSetup")}</summary>
    {opened && <>
      {busy && <p role="status">{t("storefrontWorking")}</p>}
      {error && <p className="error" role="alert">{t(error)}</p>}
      {notice && <p className="notice" role="status">{t(notice)}</p>}
      {!loaded && error && <button type="button" className="button-outline" disabled={busy}
        onClick={() => void run(() => api<StorefrontResponse>(endpoint))}>{t("storefrontReload")}</button>}
      {loaded && <form onSubmit={save}>
        <label>{t("storefrontOrigin")}
          <input type="url" required maxLength={2048} value={origin} placeholder="https://example.com"
            disabled={busy} onChange={(event) => setOrigin(event.target.value)} />
        </label>
        <label>{t("storefrontReturnUrl")}
          <input type="text" inputMode="url" required maxLength={2048} value={returnUrl}
            placeholder="https://example.com/checkout/return?session_id={CHECKOUT_SESSION_ID}"
            disabled={busy} onChange={(event) => setReturnUrl(event.target.value)} />
        </label>
        <small>{t("storefrontReturnHint", { placeholder: "{CHECKOUT_SESSION_ID}" })}</small>
        <button className="button-primary" disabled={busy || !dirty}>{t("storefrontSave")}</button>
      </form>}
      {pilotConfigured && <div className="storefront-dns">
        <button type="button" className="button-outline" disabled={busy}
          onClick={() => void refreshPilotOrders()}>{t("storefrontPilotOrders")}</button>
        {pilotOrders && (pilotOrders.length ? <ul aria-live="polite">{pilotOrders.map((order) =>
          <li key={order.id}>
            {new Date(order.createdAt).toLocaleString(i18n.language)} · {order.id.slice(0, 8)} · {
              t(order.initialPaymentStatus === "PAID" ? "storefrontOrderPaid" : "storefrontOrderUnpaid")
            }
          </li>
        )}</ul> : <p role="status">{t("storefrontNoPilotOrders")}</p>)}
      </div>}
      {proposal && !dirty && <div className="storefront-dns">
        <p>{proposal.testApprovedAt ? t("storefrontTestApproved") : t("storefrontTestPending")}</p>
        <div className="storefront-actions">
          {canApprove && challenge && !proposal.testApprovedAt &&
            <button type="button" className="button-outline" disabled={busy}
              onClick={() => void run(() => api<StorefrontResponse>(`${endpoint}/approve-test`, { revision: proposal.revision }))}>
              {t("storefrontApproveTest")}
            </button>}
          <button type="button" className="button-outline" disabled={busy}
            onClick={() => void run(() => api<StorefrontResponse>(endpoint))}>{t("storefrontReload")}</button>
        </div>
        {challenge && <details className="storefront-setup">
        <summary>{t("storefrontOptionalDns")}</summary>
        <p>{proposal.verifiedAt
          ? t("storefrontVerifiedAt", { date: new Date(proposal.verifiedAt).toLocaleString(i18n.language) })
          : t("storefrontPending")}</p>
          <p>{t("storefrontDnsInstructions")}</p>
          <label>{t("storefrontDnsName")}<input readOnly value={challenge.name} /></label>
          <button type="button" className="button-outline"
            onClick={() => void copy(challenge.name)}>{t("storefrontCopyName")}</button>
          <label>{t("storefrontDnsValue")}<input readOnly value={challenge.value} /></label>
          <button type="button" className="button-outline"
            onClick={() => void copy(challenge.value)}>{t("storefrontCopyValue")}</button>
          <div className="storefront-actions">
            <button type="button" className="button-outline" disabled={busy}
              onClick={() => void run(() => api<StorefrontResponse>(`${endpoint}/verify`, { revision: proposal.revision }))}>
              {t("storefrontVerify")}
            </button>
          </div>
        </details>}
      </div>}
    </>}
  </details>;
}
