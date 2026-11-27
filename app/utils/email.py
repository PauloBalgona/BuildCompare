import os
import smtplib
from email.message import EmailMessage
from flask import current_app


def _send_reset_email(recipient_email: str, reset_link: str) -> bool:
    smtp_server = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("MAIL_PORT", "587"))
    use_tls = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    username = os.environ.get("MAIL_USERNAME", "").strip()
    password = os.environ.get("MAIL_PASSWORD", "").strip()
    sender = os.environ.get("MAIL_DEFAULT_SENDER", username).strip()

    if not username or not password:
        current_app.logger.warning(
            "SMTP credentials are not configured. Reset link for %s: %s",
            recipient_email,
            reset_link,
        )
        return False

    msg = EmailMessage()
    msg["Subject"] = "Reset Your BuildCompare Password"
    msg["From"] = sender or username
    msg["To"] = recipient_email

    msg.set_content(
        f"Hi,\n\n"
        f"We received a request to reset your BuildCompare password.\n"
        f"Click the link below to set a new password (valid for 30 minutes):\n"
        f"{reset_link}\n\n"
        f"If you did not request this, you can safely ignore this email.\n\n"
        f"— BuildCompare"
    )

    msg.add_alternative(
        f"""
        <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #111827; max-width: 520px;">
          <h2 style="margin-bottom: 8px;">Reset your BuildCompare password</h2>
          <p style="color: #4b5563; margin-top: 0;">
            We received a request to reset the password for your account. Click the button below to choose a new password:
          </p>
          <p style="margin: 24px 0;">
            <a href="{reset_link}"
               style="display: inline-block; padding: 12px 20px; background-color: #111827; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 600;">
              Reset Password
            </a>
          </p>
          <p style="font-size: 13px; color: #6b7280;">
            This link will expire in 30 minutes. If you didn't request a password reset, you can ignore this message.
          </p>
          <p style="font-size: 12px; color: #9ca3af; word-break: break-all;">
            Or copy and paste this URL into your browser:<br>
            {reset_link}
          </p>
        </div>
        """,
        subtype="html",
    )

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=15) as server:
            if use_tls:
                server.starttls()
            server.login(username, password)
            server.send_message(msg)
        return True
    except Exception as exc:
        current_app.logger.error("Failed to send reset email to %s: %s", recipient_email, exc)
        return False