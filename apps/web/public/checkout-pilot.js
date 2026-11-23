(() => {
  for (const widget of document.querySelectorAll("[data-kuzushi-checkout]")) {
    const endpoint = widget.getAttribute("data-kuzushi-checkout");
    const button = widget.querySelector("[data-kuzushi-open]");
    const close = widget.querySelector("[data-kuzushi-close]");
    const mount = widget.querySelector("[data-kuzushi-mount]");
    const status = widget.querySelector("[data-kuzushi-status]");
    if (!endpoint || !button || !close || !mount || !status) continue;

    const returned = new URL(window.location.href);
    if (returned.searchParams.has("session_id")) {
      returned.searchParams.delete("session_id");
      window.history.replaceState(null, "", returned.pathname + returned.search + returned.hash);
      status.textContent = "Returned from test checkout. Check Kuzushi Pay for the payment result.";
    }

    let checkout;
    close.addEventListener("click", () => {
      checkout?.destroy();
      checkout = undefined;
      close.hidden = true;
      button.disabled = false;
      status.textContent = "Test checkout closed.";
      button.focus();
    });
    button.addEventListener("click", async () => {
      if (button.disabled) return;
      button.disabled = true;
      status.textContent = "Opening test checkout…";
      try {
        if (typeof window.Stripe !== "function") throw new Error("Stripe.js unavailable");
        const response = await fetch(endpoint, {
          method: "POST",
          credentials: "omit",
          redirect: "error",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ requestId: crypto.randomUUID() })
        });
        if (!response.ok) throw new Error("Checkout unavailable");
        const { clientSecret, publishableKey } = await response.json();
        if (!/^pk_test_[A-Za-z0-9]+$/.test(publishableKey) || !/^cs_test_[A-Za-z0-9]+_secret_/.test(clientSecret)) {
          throw new Error("Invalid test checkout");
        }
        checkout = await window.Stripe(publishableKey).initEmbeddedCheckout({
          fetchClientSecret: async () => clientSecret
        });
        checkout.mount(mount);
        close.hidden = false;
        status.textContent = "";
      } catch {
        checkout?.destroy();
        checkout = undefined;
        status.textContent = "Test checkout could not open. Please try again.";
        button.disabled = false;
      }
    });
  }
})();
