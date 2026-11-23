export type StripePrice = {
  id: string; object: string; active: boolean; livemode: boolean;
  currency: string; unit_amount: number | null; type: string;
  billing_scheme: string; custom_unit_amount: object | null; transform_quantity: object | null;
  product: string | { id: string };
  recurring: { interval: string; interval_count: number; usage_type: string; trial_period_days: number | null } | null;
};

export function matchesStripePrice(price: StripePrice, expected: {
  mode: "TEST" | "LIVE"; priceId?: string; productId: string; amountCents: number;
  billing: "ONE_TIME" | "RECURRING"; interval: "DAY" | "WEEK" | "MONTH" | "YEAR" | null;
}, options: { allowInactive?: boolean } = {}): boolean {
  if (!price) return false;
  const productId = typeof price.product === "string" ? price.product : price.product?.id;
  const recurring = expected.billing === "RECURRING";
  return price.object === "price" && typeof price.id === "string" &&
    /^price_[A-Za-z0-9]+$/.test(price.id) && (!expected.priceId || price.id === expected.priceId) &&
    (price.active === true || (options.allowInactive === true && price.active === false)) &&
    price.livemode === (expected.mode === "LIVE") &&
    price.currency === "usd" && price.unit_amount === expected.amountCents &&
    price.billing_scheme === "per_unit" && price.custom_unit_amount === null && price.transform_quantity === null &&
    productId === expected.productId && price.type === (recurring ? "recurring" : "one_time") &&
    (recurring ? price.recurring?.interval === expected.interval?.toLowerCase() &&
      price.recurring?.interval_count === 1 && price.recurring?.usage_type === "licensed" &&
      price.recurring?.trial_period_days === null : price.recurring === null);
}
