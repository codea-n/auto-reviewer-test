import os
import logging
import resend

logger = logging.getLogger(__name__)

resend.api_key = os.getenv("RESEND_API_KEY", "")

def send_review_email(
    to_email: str,
    repo: str,
    pr_number: int,
    verdict: str,
    review_id: str,
) -> bool:
    """
    Sends a review notification email to the PR author.
    Returns True if sent successfully, False otherwise.
    Never raises — email failure must not break the review pipeline.
    """
    if not resend.api_key:
        logger.warning("RESEND_API_KEY not set — skipping email")
        return False

    is_approved = "APPROVE" in verdict.upper()
    verdict_emoji = "✅" if is_approved else "⚠️"
    verdict_label = "Approved" if is_approved else "Changes Requested"

    # Extract first 300 chars of verdict as preview
    preview = verdict[:300].strip()
    if len(verdict) > 300:
        preview += "..."

    dashboard_url = os.getenv("FRONTEND_URL", "https://revuops-web.vercel.app")
    review_url = f"{dashboard_url}/dashboard/reviews/{review_id}"

    try:
        resend.Emails.send({
            "from": "RevuOps <onboarding@resend.dev>",
            "to": [to_email],
            "subject": f"{verdict_emoji} PR #{pr_number} reviewed — {repo}",
            "html": f"""
<!DOCTYPE html>
<html>
<body style="font-family: sans-serif; background: #000; color: #fff; padding: 32px; max-width: 600px; margin: 0 auto;">
  <h1 style="font-size: 20px; font-weight: bold; margin-bottom: 4px;">RevuOps</h1>
  <p style="color: #666; font-size: 14px; margin-bottom: 32px;">Autonomous code review</p>

  <h2 style="font-size: 16px; margin-bottom: 8px;">
    {verdict_emoji} {repo} — PR #{pr_number}
  </h2>
  <p style="color: #888; font-size: 14px; margin-bottom: 24px;">
    Verdict: <strong style="color: {'#4ade80' if is_approved else '#f87171'};">{verdict_label}</strong>
  </p>

  <div style="background: #111; border: 1px solid #222; border-radius: 8px; padding: 16px; margin-bottom: 24px;">
    <p style="color: #aaa; font-size: 13px; line-height: 1.6; margin: 0;">{preview}</p>
  </div>

  <a href="{review_url}"
     style="display: inline-block; background: #fff; color: #000; padding: 12px 24px;
            border-radius: 6px; text-decoration: none; font-weight: 600; font-size: 14px;">
    View Full Review →
  </a>

  <p style="color: #444; font-size: 12px; margin-top: 32px;">
    Sent by RevuOps • <a href="{dashboard_url}" style="color: #666;">revuops-web.vercel.app</a>
  </p>
</body>
</html>
""",
        })
        logger.info(f"Review email sent to {to_email} for PR #{pr_number}")
        return True
    except Exception as e:
        logger.error(f"Failed to send review email: {e}")
        return False