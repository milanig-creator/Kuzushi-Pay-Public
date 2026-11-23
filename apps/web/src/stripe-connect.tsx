import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "./api";

type Status = "available" | "pending" | "connected" | "unavailable";

export function StripeConnect({ businessId, disabled, onError, canLeave }: {
  businessId: string; disabled: boolean; onError(error: unknown): void; canLeave(): boolean;
}) {
  const { t } = useTranslation();
  const endpoint = `/api/businesses/${businessId}/stripe/connect`;
  const [status, setStatus] = useState<Status>();
  const [busy, setBusy] = useState(false);

  async function refresh() {
    setBusy(true);
    try {
      setStatus((await api<{ status: Status }>(endpoint)).status);
    } catch (error) { onError(error); }
    finally { setBusy(false); }
  }

  useEffect(() => {
    const url = new URL(window.location.href);
    if (!url.searchParams.has("stripe_connect") || url.searchParams.get("business") !== businessId) return;
    url.searchParams.delete("stripe_connect");
    url.searchParams.delete("business");
    window.history.replaceState(null, "", url);
    void refresh();
  }, [businessId]);

  async function start() {
    if (!canLeave()) return;
    setBusy(true);
    try {
      const result = await api<{ authorizationUrl: string }>(endpoint, {});
      window.location.assign(result.authorizationUrl);
    } catch (error) { onError(error); setBusy(false); }
  }

  return <>
    {status === "connected" && <span role="status">{t("stripeConnectConnected")}</span>}
    {status === "pending" && <span role="status">{t("stripeConnectPending")}</span>}
    {status === "unavailable" && <span role="status">{t("stripeSandboxUnavailable")}</span>}
    {status !== "connected" && status !== "unavailable" && <button type="button" className="button-outline"
      disabled={disabled || busy} onClick={() => void start()}>
      {t(status === "pending" ? "stripeConnectContinue" : "stripeConnectStart")}
    </button>}
    <button type="button" className="button-outline" disabled={disabled || busy}
      onClick={() => void refresh()}>{t("stripeConnectRefresh")}</button>
  </>;
}
