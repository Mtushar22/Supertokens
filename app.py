from flask import Flask, abort, g
from supertokens_python import (
    get_all_cors_headers,
    init,
    InputAppInfo,
    SupertokensConfig,
)
from flask_cors import CORS
from supertokens_python.framework.flask import Middleware
from supertokens_python.recipe import (
    session,
    dashboard,
    emailpassword,
    userroles,
)
from supertokens_python.recipe.session.framework.flask import verify_session
from supertokens_python.recipe.session import SessionContainer
from supertokens_python.recipe.userroles.syncio import (
    create_new_role_or_add_permissions,
    add_role_to_user,
)
from supertokens_python.recipe.userroles.interfaces import UnknownRoleError
from supertokens_python.recipe.userroles import UserRoleClaim, PermissionClaim


app = Flask(__name__)
Middleware(app)


init(
    app_info=InputAppInfo(
        app_name="Test",
        api_domain="http://localhost:5000",
        website_domain="http://localhost:9000",
        api_base_path="/auth",
        website_base_path="/auth",
    ),
    supertokens_config=SupertokensConfig(
        # https://try.supertokens.com is for demo purposes. Replace this with the address of your core instance (sign up on supertokens.com), or self host a core.
        connection_uri="http://localhost:3567",
        # api_key=<API_KEY(if configured)>
    ),
    framework="flask",
    recipe_list=[
        session.init(),  # initializes session features
        dashboard.init(),
        emailpassword.init(),
        userroles.init(),
    ],
)

CORS(
    app=app,
    origins=["http://localhost:9000"],
    supports_credentials=True,
    allow_headers=["Content-Type"] + get_all_cors_headers(),
)


@app.route("/protected-route", methods=["GET"])
@verify_session(None, True)
def protectedRoute():
    session: SessionContainer = g.supertokens
    user_id = session.get_user_id()
    return user_id


@app.route("/create-role", methods=["POST"])
@verify_session()
def createRole():
    res = create_new_role_or_add_permissions("admin", ["read"])
    if not res.created_new_role:
        # The role already existed
        pass
    return "OK"


@app.route("/add-user-to-role", methods=["POST"])
# @verify_session()
def addUserToRole():
    # fetch userID from query params
    res = add_role_to_user("public", "bf7294de-37e9-4dce-b5fd-97e0e681013b", "admin")
    if isinstance(res, UnknownRoleError):
        # No such role exists
        return

    if res.did_user_already_have_role:
        # User already had this role
        pass
    return "OK"


@app.route("/rbac", methods=["GET"])
@verify_session(
    override_global_claim_validators=lambda global_validators, session, user_context: global_validators
    + [UserRoleClaim.validators.includes("admin")] + [PermissionClaim.validators.includes("write")]
)
def rbac():
    return "OK"

@app.route("/<path:u_path>")
def catch_all(u_path: str):
    abort(404)
