import hmac
import hashlib
import logging
import os
import json
import httpx
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request
from app.agents.graph import review_graph
from app.api.github_client import post_pr_comment
from app.db.repository import save_review
from app.db.supabase_client import get_client
from app.api.email import send_review_email


router = APIRouter()
logger = logging.getLogger(__name__)


def _lookup_user(installation_id: int) -> dict:
    """
    Given installation_id, returns user_id and email.
    Queries installations table then auth.users for email.
    """
    if not installation_id:
        return {}
    try:
        client = get_client()
        # Get user_id from installations
        res = client.table("installations")\
            .select("user_id")\
            .eq("installation_id", installation_id)\
            .limit(1)\
            .execute()
        if not res.data:
            return {}
        user_id = res.data[0]["user_id"]

        # Get email from auth.users using admin client
        user_res = client.auth.admin.get_user_by_id(user_id)
        email = user_res.user.email if user_res.user else None

        return {"user_id": user_id, "email": email}
    except Exception as e:
        logger.warning(f"Could not look up user for installation {installation_id}: {e}")
    return {}


async def _fetch_diff(diff_url: str) -> str:
    token = os.getenv("GITHUB_TOKEN")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.diff",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    async with httpx.AsyncClient() as client:
        response = await client.get(diff_url, headers=headers, follow_redirects=True)
        response.raise_for_status()
        return response.text


async def _run_review(pr_info: dict):
    try:
        logger.info(f"Fetching diff for PR #{pr_info['pr_number']}")
        diff = await _fetch_diff(pr_info["diff_url"])
        logger.info(f"Diff fetched: {len(diff)} chars")

        initial_state = {
            "pr_number":              pr_info["pr_number"],
            "repo_full_name":         pr_info["repo"],
            "diff":                   diff,
            "rag_context":            "",
            "security_findings":      None,
            "performance_findings":   None,
            "architecture_findings":  None,
            "final_review":           None,
            "model_version":          None,
            "error":                  None,
        }

        result = await review_graph.ainvoke(initial_state)

        if result.get("error"):
            logger.error(f"Graph error: {result['error']}")
            return

        review_id = save_review(
            pr_number             = pr_info["pr_number"],
            repo                  = pr_info["repo"],
            review_text           = result.get("final_review", ""),
            security_findings     = result.get("security_findings"),
            performance_findings  = result.get("performance_findings"),
            architecture_findings = result.get("architecture_findings"),
            model_version         = result.get("model_version", "unknown"),
            user_id               = pr_info.get("user_id"),   # ← new
        )

        comment_body = result.get("final_review", "") + f"\n\n<!-- autoreview_id:{review_id} -->"
        await post_pr_comment(
            repo_full_name = pr_info["repo"],
            pr_number      = pr_info["pr_number"],
            body           = comment_body,
        )
        author_email = pr_info.get("author_email")
        if author_email:
            send_review_email(
                to_email=author_email,
                repo=pr_info["repo"],
                pr_number=pr_info["pr_number"],
                verdict=result.get("final_review", ""),
                review_id=review_id,
            )

        logger.info(f"Review {review_id} posted to PR #{pr_info['pr_number']}")

    except Exception as e:
        import traceback
        logger.error(f"Review failed for PR #{pr_info['pr_number']}: {e}")
        logger.error(traceback.format_exc())


@router.post("/webhook")                          # ← fixed: was /webhook/github
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
):
    payload = await request.body()
    _verify_signature(payload, x_hub_signature_256)
    body = json.loads(payload)

    action = body.get("action")

    if x_github_event == "pull_request" and action in ("opened", "synchronize"):
        pr = body["pull_request"]

        # Extract installation_id GitHub sends with every webhook
        installation_id = body.get("installation", {}).get("id")
        # Look up which user owns this installation
        user_info = _lookup_user(installation_id)
        user_id = user_info.get("user_id")
        author_email = user_info.get("email")

        logger.info(f"Webhook: installation_id={installation_id}, user_id={user_id}, email={author_email}")

        pr_info = {
            "pr_number":   pr["number"],
            "title":       pr["title"],
            "author":      pr["user"]["login"],
            "repo":        body["repository"]["full_name"],
            "base_branch": pr["base"]["ref"],
            "head_branch": pr["head"]["ref"],
            "diff_url":    pr["diff_url"],
            "user_id":     user_id,               # ← new
            "author_email": author_email,   # ← new

        }

        background_tasks.add_task(_run_review, pr_info)
        return {"status": "queued", "pr": pr_info}

    return {"status": "ignored", "event": x_github_event, "action": action}


def _verify_signature(payload: bytes, signature_header: str):
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="Webhook secret not configured")
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing signature header")

    expected = "sha256=" + hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=401, detail="Invalid signature")