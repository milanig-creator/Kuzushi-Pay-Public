import type { RecoveryMail } from "./password-recovery.js";

export function recoveryMessage(from: string, mail: RecoveryMail) {
  const spanish = mail.language === "es";
  return {
    from, to: mail.to,
    subject: spanish ? "Restablece tu contraseña de Kuzushi Pay" : "Reset your Kuzushi Pay password",
    text: spanish
      ? `Para restablecer tu contraseña, abre este enlace en los próximos 30 minutos:\n\n${mail.link}\n\nSi no solicitaste este cambio, ignora este mensaje.`
      : `To reset your password, open this link within 30 minutes:\n\n${mail.link}\n\nIf you did not request this change, ignore this message.`
  };
}
