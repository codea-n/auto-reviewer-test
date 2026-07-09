import os
import time
import asyncio
import logging
import httpx
import jwt as pyjwt
from jwt import PyJWKClient
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from app.db.supabase_client import get_client
from app.api.security import limiter

logger = logging.getLogger(__name__)
router = APIRouter()


def _make_jwks_client() -> PyJWKClient:
    jwks_url = os.getenv("SUPABASE_JWKS_URL")
    if not jwks_url:
        raise RuntimeError("SUPABASE_JWKS_URL environment variable not set")
    return PyJWKClient(
        jwks_url,
        cache_keys=False,   # LRU has no TTL — unsafe for key rotation
        cache_jwk_set=True, # cache full JWKS response (default)
        lifespan=300,       # refresh every 5 minutes
    )


# Module-level — initialized once at startup, shared across all requests.
# Avoids lazy-init race condition and avoids creating a new client per request.
_jwks_client: PyJWKClient = _make_jwks_client()


async def verify_supabase_token(request: Request) -> str:
    """
    Verifies a Supabase JWT using ES256 via JWKS.
    Security decisions:
    - PyJWKClient handles kid-based key selection and rotation automatically.
    - get_signing_key_from_jwt() uses blocking urllib internally.
      asyncio.to_thread() offloads it to a thread pool — event loop stays free.
    - algorithms=["ES256"]: explicit whitelist prevents algorithm confusion attacks.
    - audience="authenticated": Supabase standard claim for user tokens.
    - issuer=SUPABASE_ISSUER: prevents tokens from other Supabase projects.
    - options={"require": [...]}: rejects tokens that are missing required claims.
    - exp validated automatically by PyJWT.
    - PyJWT>=2.13.0 required: fixes algorithm bypass, SSRF, and DoS CVEs.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing auth token")
    token = auth_header.replace("Bearer ", "")
    issuer = os.getenv("SUPABASE_ISSUER")
    if not issuer:
        raise HTTPException(status_code=500, detail="SUPABASE_ISSUER not configured")
    try:
        # Offload blocking urllib call to thread pool
        signing_key = await asyncio.to_thread(
            _jwks_client.get_signing_key_from_jwt, token
        )
        payload = pyjwt.decode(
            token,
            signing_key.key,
            algorithms=["ES256"],
            audience="authenticated",
            issuer=issuer,
            options={
                "require": ["exp", "iss", "sub", "aud"],
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True,
            },
        )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token missing sub claim")
        return user_id
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except pyjwt.InvalidAudienceError:
        raise HTTPException(status_code=401, detail="Invalid token audience")
    except pyjwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail="Invalid token issuer")
    except pyjwt.MissingRequiredClaimError as e:
        raise HTTPException(status_code=401, detail=f"Missing required claim: {e}")
    except pyjwt.InvalidTokenError as e:
        logger.warning(f"JWT verification failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected token verification error: {e}")
        raise HTTPException(status_code=401, detail="Token verification failed")


def _generate_jwt() -> str:
    app_id = os.getenv("GITHUB_APP_ID")
    private_key = os.getenv("GITHUB_APP_PRIVATE_KEY")
    if not private_key:
        pem_path = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH")
        if not pem_path:
            raise ValueError("Either GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH must be set")
        with open(pem_path, "r") as f:
            private_key = f.read()
    if not app_id:
        raise ValueError("GITHUB_APP_ID must be set")
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 540,
        "iss": app_id,
    }
    return pyjwt.encode(payload, private_key, algorithm="RS256")


async def get_installation_repos(installation_id: int) -> list[dict]:
    jwt_token = _generate_jwt()
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.github+json",
            }
        )
        if token_resp.status_code != 201:
            raise HTTPException(status_code=400, detail="Failed to get installation token")
        installation_token = token_resp.json()["token"]
        repos_resp = await client.get(
            "https://api.github.com/installation/repositories",
            headers={
                "Authorization": f"Bearer {installation_token}",
                "Accept": "application/vnd.github+json",
            }
        )
        if repos_resp.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch repositories")
        return repos_resp.json().get("repositories", [])


class InstallRequest(BaseModel):
    installation_id: int
    account_login: str
    # user_id intentionally absent — derived from verified JWT, never trusted from body


@router.post("/github/install")
@limiter.limit("10/minute")
async def handle_installation(
    request: Request,
    body: InstallRequest,
    user_id: str = Depends(verify_supabase_token),
):
    supabase = get_client()

    # Upsert the installation record itself. on_conflict="installation_id"
    # is required because GitHub sends the same installation_id every time
    # a repo is added/removed under an existing install — without this,
    # Postgres tries a plain INSERT and hits the unique constraint.
    supabase.table("installations").upsert(
        {
            "user_id": user_id,
            "installation_id": body.installation_id,
            "account_login": body.account_login,
        },
        on_conflict="installation_id",
    ).execute()

    # Fetch the CURRENT set of repos GitHub says this installation has access to.
    # This is the source of truth — our DB must converge to match it exactly.
    repos = await get_installation_repos(body.installation_id)
    current_repo_ids = [repo["id"] for repo in repos]

    # Bulk upsert all currently-installed repos in a single request instead of
    # looping — one network call, and no risk of a partial write if repo N
    # in a loop were to fail after N-1 already succeeded.
    #
    # on_conflict="installation_id,repo_id" matches the composite UNIQUE
    # constraint we just added. This is the correct key because a single
    # installation can cover many repos (installation_id repeats), and the
    # same repo_id should never collide across two different installations'
    # rows — each (installation, repo) pair is its own identity.
    if repos:
        rows = [
            {
                "user_id": user_id,
                "installation_id": body.installation_id,
                "repo_full_name": repo["full_name"],
                "repo_id": repo["id"],
            }
            for repo in repos
        ]
        supabase.table("repositories").upsert(
            rows,
            on_conflict="installation_id,repo_id",
        ).execute()

    # Remove repos that are no longer part of this installation (e.g. user
    # revoked access to a repo in GitHub's install settings). Without this,
    # stale repos remain in the dashboard forever and the backend may keep
    # attempting reviews on repos it no longer has GitHub access to.
    #
    # This runs AFTER the upsert above intentionally: if the upsert fails
    # partway (network blip, etc.), the worst case is stale extra rows —
    # not accidentally deleted rows that never got re-inserted.
    delete_query = supabase.table("repositories") \
        .delete() \
        .eq("installation_id", body.installation_id)

    if current_repo_ids:
        delete_query = delete_query.not_.in_("repo_id", current_repo_ids)

    delete_query.execute()

    logger.info(
        f"Installation {body.installation_id} synced for user {user_id} "
        f"with {len(repos)} repos"
    )
    return {"status": "ok", "repos_connected": len(repos)}


@router.get("/github/repos")
@limiter.limit("30/minute")
async def get_user_repos(
    request: Request,
    user_id: str = Depends(verify_supabase_token),
):
    supabase = get_client()
    res = supabase.table("repositories")\
        .select("*")\
        .eq("user_id", user_id)\
        .execute()
    return {"repos": res.data}