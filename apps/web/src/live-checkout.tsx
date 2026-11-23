import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "./api";

type Checkout = { mount(element: HTMLElement): void; destroy(): void };
type StripeFactory = (key: string) => {
  initEmbeddedCheckout(options: { fetchClientSecret(): Promise<string> }): Promise<Checkout>;
};
type Order = { id: string; name: string; createdAt: string; status: "PAID" | "UNPAID"; quantity: number | null };

let stripeLoading: Promise<StripeFactory> | undefined;
function loadStripe() {
  stripeLoading ??= new Promise<StripeFactory>((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://js.stripe.com/v3/";
    script.onload = () => {
      const stripe = (window as Window & { Stripe?: StripeFactory }).Stripe;
      if (stripe) resolve(stripe);
      else reject(new Error("Stripe.js unavailable"));
    };
    script.onerror = () => reject(new Error("Stripe.js unavailable"));
    document.head.append(script);
  }).catch((error: unknown) => {
    stripeLoading = undefined;
    throw error;
  });
  return stripeLoading;
}

export function LiveCheckout({ businessId, products, onError }: {
  businessId: string;
  products: { id: string; name: string }[];
  onError(error: unknown): void;
}) {
  const { t, i18n } = useTranslation();
  const mount = useRef<HTMLDivElement>(null);
  const checkout = useRef<Checkout | null>(null);
  const active = useRef(false);
  const starting = useRef(false);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loadingOrders, setLoadingOrders] = useState(false);
  const [orders, setOrders] = useState<Order[]>();
  const [error, setError] = useState("");
  const [ordersError, setOrdersError] = useState(false);
  const base = `/api/businesses/${encodeURIComponent(businessId)}`;

  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      checkout.current?.destroy();
      checkout.current = null;
    };
  }, []);

  async function start(draftId: string) {
    if (starting.current || checkout.current) return;
    starting.current = true;
    setBusy(true);
    setError("");
    let embedded: Checkout | undefined;
    try {
      const stripe = await loadStripe();
      if (!active.current) return;
      const session = await api<{ clientSecret: string; publishableKey: string }>(
        `${base}/product-drafts/${encodeURIComponent(draftId)}/checkout`, { requestId: crypto.randomUUID() }
      );
      if (!active.current) return;
      embedded = await stripe(session.publishableKey).initEmbeddedCheckout({
        fetchClientSecret: async () => session.clientSecret
      });
      if (!active.current || !mount.current) {
        embedded.destroy();
        return;
      }
      embedded.mount(mount.current);
      checkout.current = embedded;
      setOpen(true);
    } catch (failure) {
      embedded?.destroy();
      if (active.current) {
        setError(failure instanceof ApiError && failure.message === "CHECKOUT_UNAVAILABLE"
          ? "liveCheckoutUnavailable" : "liveCheckoutFailed");
        if (failure instanceof ApiError && failure.message === "UNAUTHENTICATED") onError(failure);
      }
    } finally {
      starting.current = false;
      if (active.current) setBusy(false);
    }
  }

  async function refreshOrders() {
    setLoadingOrders(true);
    setOrdersError(false);
    try {
      const result = await api<{ orders: Order[] }>(`${base}/live-orders`);
      if (active.current) setOrders(result.orders);
    } catch (failure) {
      if (active.current) {
        setOrdersError(true);
        if (failure instanceof ApiError && failure.message === "UNAUTHENTICATED") onError(failure);
      }
    } finally {
      if (active.current) setLoadingOrders(false);
    }
  }

  return <section>
    {products.length > 0 && <>
      <h3>{t("liveCheckoutPreview")}</h3>
      <p>{t("liveCheckoutPreviewHelp")}</p>
      <ul>{products.map((product) => <li className="business" key={product.id}>
        <strong>{product.name}</strong>
        <button type="button" className="button-outline" disabled={busy || open}
          onClick={() => void start(product.id)}>{t("openLiveCheckout")}</button>
      </li>)}</ul>
    </>}
    {busy && <p role="status">{t("loading")}</p>}
    {error && <p className="error" role="alert">{t(error)}</p>}
    <div ref={mount} />
    {open && <button type="button" className="button-outline" onClick={() => {
      checkout.current?.destroy();
      checkout.current = null;
      setOpen(false);
    }}>{t("closeLiveCheckout")}</button>}
    <h3>{t("liveOrders")}</h3>
    <button type="button" className="button-outline" disabled={loadingOrders}
      onClick={() => void refreshOrders()}>{t("refreshLiveOrders")}</button>
    {ordersError && <p className="error" role="alert">{t("errorGeneric")}</p>}
    {orders && (orders.length ? <ul>{orders.map((order) => <li className="business" key={order.id}>
      <strong>{order.name}</strong>
      <time dateTime={order.createdAt}>{new Date(order.createdAt).toLocaleString(i18n.language)}</time>
      <span>{t(order.status === "PAID" ? "liveOrderPaid" : "liveOrderUnpaid")}</span>
      {order.quantity !== null && <span>{t("liveOrderQuantity", { count: order.quantity })}</span>}
    </li>)}</ul> : <p>{t("noLiveOrders")}</p>)}
  </section>;
}
