from fastapi import Header, HTTPException
from pydantic import BaseModel

import os
import secrets

# Token generated on CMD with:
# python -c "import secrets; print(secrets.token_urlsafe(32))"
# Saved in .env.example, which is then .gitignored.
# The key needs to be sent from end-user to end-user.

class Principal(BaseModel):
    user_id: str
    roles: set[str] = set()
    scopes: set[str] = set()


# TODO Replace with real auth: verify token, extract roles/scopes.
def get_current_principal(
    authorisation: str | None = Header(default=None, alias="Authorization"),
) -> Principal:
    """
    For de
        accept Bearer tokens like 'Bearer demo-token-<role>'.
    Parameters:
        authorisation is the Authorization header, expected to be a Bearer token.

    Returns:
        a Principal class object with user_id, roles, and scopes, if and only if
        the user-supplied key corresponds to the key in .env. Else, error and
        crashes.
    """

    # If 'authorisation' is an empty string,
    # or if 'authorisation' does not have word 'bearer ...' in front.
    if not authorisation or not authorisation.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")

    token = authorisation.split(" ", 1)[1]

    expected = os.environ.get("APP_API_KEY")
    if not expected:
      raise HTTPException(status_code=500, detail="Server missing APP_API_KEY")

    if not secrets.compare_digest(token, expected):
      raise HTTPException(status_code=401, detail="Invalid API key")

    return Principal(
      user_id="cli-client",
      roles={"utility.read", "conversion.run"},
      scopes={"miles:convert"},
    )
