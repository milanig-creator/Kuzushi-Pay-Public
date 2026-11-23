import { describe, expect, it } from "vitest";
import nodemailer from "nodemailer";
import { recoveryMessage } from "./recovery-mail.js";

describe("recovery email", () => {
  it.each(["en", "es"] as const)("renders a %s reset message using the mail transport", async (language) => {
    const transport = nodemailer.createTransport({ streamTransport: true, buffer: true });
    const link = `https://pay.example.com/#reset=${"a".repeat(64)}`;
    const message = recoveryMessage("sender@example.com", { to: "owner@example.com", link, language });
    const result = await transport.sendMail(message);
    expect(result.envelope).toEqual({ from: "sender@example.com", to: ["owner@example.com"] });
    const unfolded = result.message.toString().replace(/=\r\n/g, "").replace(/=3D/g, "=");
    expect(unfolded).toContain(link);
    expect(message.subject).toBe(language === "es" ? "Restablece tu contraseña de Kuzushi Pay" : "Reset your Kuzushi Pay password");
    transport.close();
  });
});
