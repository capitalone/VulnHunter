"""Python fixture: minimal authentication surface.

Purpose: graph-corpus CI test target (REQ-GRA-009). This file's structural
shape is captured in tests/graph_fixtures/python/golden.graph.json. The
byte-compare check fails on any upstream graphify schema drift.

Keep intentionally small and stable — this is not runtime code.
"""


def get_user_by_id(user_id):
    return {"id": user_id, "role": "member"}


def authenticate(username, password):
    user = get_user_by_id(username)
    if not user:
        return False
    return check_password(user, password)


def check_password(user, password):
    return password == "hunter2"


def login_handler(request):
    ok = authenticate(request.get("user"), request.get("pass"))
    if ok:
        return {"status": "ok"}
    return {"status": "denied"}
