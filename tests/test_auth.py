from __future__ import annotations

from conftest import write_tree

from silentbug_lite.scan import scan

UNPROTECTED = "auth.unprotected-route"
DESTRUCTIVE = "auth.destructive-no-auth"

FASTAPI = """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/a")
def a(user=Depends(get_current_user)): ...

@router.get("/b")
def b(user=Depends(get_current_user)): ...

@router.post("/c")
def c(user=Depends(get_current_user)): ...
"""


def rules(findings):
    return [(f.rule_id, f.line) for f in findings]


# --- auth.unprotected-route ------------------------------------------------------


def test_fastapi_route_that_breaks_the_file_pattern(check):
    found = check(FASTAPI + '\n@router.get("/d")\ndef d(): ...\n')
    assert rules(found) == [(UNPROTECTED, 14)]
    assert "get_current_user" in found[0].message


def test_fastapi_dependencies_on_the_router_or_decorator_count(check):
    code = """
from fastapi import APIRouter, Depends
router = APIRouter(dependencies=[Depends(get_current_user)])

@router.get("/a")
def a(): ...

@router.get("/b", dependencies=[Depends(require_admin)])
def b(): ...

@router.get("/c")
def c(): ...
"""
    assert check(code) == []


def test_annotated_alias_from_another_file_counts(tmp_path):
    write_tree(
        tmp_path,
        {
            "deps.py": "from typing import Annotated\n"
            "CurrentUser = Annotated[User, Depends(get_current_user)]\n",
            "routes.py": FASTAPI.replace("user=Depends(get_current_user)", "user: CurrentUser")
            + '\n@router.get("/d")\ndef d(user: CurrentUser): ...\n',
        },
    )
    assert scan(tmp_path).findings == []


def test_fully_public_file_and_too_few_routes_are_fine(check):
    public = """
from fastapi import APIRouter
router = APIRouter()

@router.get("/a")
def a(): ...

@router.get("/b")
def b(): ...

@router.get("/c")
def c(): ...
"""
    assert check(public) == []
    few = """
from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/a")
def a(user=Depends(get_current_user)): ...

@router.get("/x")
def x(): ...
"""
    assert check(few) == []


def test_signup_and_stricter_checks_are_not_flagged(check):
    code = FASTAPI + """
@router.post("/signup")
def register_user(body: dict): ...

@router.get("/admin", dependencies=[Depends(get_current_active_superuser)])
def admin_stats(): ...
"""
    assert check(code) == []


def test_express_route_without_the_usual_middleware(check):
    code = """
const express = require("express");
const router = express.Router();
router.get("/a", requireAuth, (req, res) => res.json(a));
router.get("/b", requireAuth, (req, res) => res.json(b));
router.post("/c", requireAuth, (req, res) => res.json(c));
router.get("/d", (req, res) => res.json(d));
"""
    assert rules(check(code, name="routes.js")) == [(UNPROTECTED, 6)]


def test_express_use_middleware_protects_later_routes(check):
    code = """
const express = require("express");
const app = express();
app.get("/health", (req, res) => res.send("ok"));
app.use(authenticate);
app.delete("/users/:id", (req, res) => remove(req.params.id));
"""
    assert check(code, name="server.js") == []


# --- auth.destructive-no-auth ----------------------------------------------------


def test_flask_delete_route_with_no_auth(check):
    code = """
from flask import Flask
app = Flask(__name__)

@app.route("/users/<int:id>", methods=["DELETE"])
def delete_user(id):
    db.delete(id)
"""
    found = check(code)
    assert rules(found) == [(DESTRUCTIVE, 5)]


def test_flask_destructive_route_with_login_required_is_fine(check):
    code = """
from flask import Flask
app = Flask(__name__)

@app.route("/users/<int:id>/ban", methods=["POST"])
@login_required
def ban_user(id):
    db.ban(id)
"""
    assert check(code) == []


def test_express_admin_delete_with_no_auth(check):
    code = """
const express = require("express");
const app = express();
app.delete("/admin/users/:id", async (req, res) => {
  await db.remove(req.params.id);
});
"""
    assert rules(check(code, name="admin.js")) == [(DESTRUCTIVE, 3)]


def test_django_view_that_deletes_without_auth(check):
    code = """
from django.views.decorators.http import require_POST

@require_POST
def delete_account(request, pk):
    Account.objects.filter(pk=pk).delete()
"""
    assert rules(check(code, name="views.py")) == [(DESTRUCTIVE, 4)]


def test_django_rest_viewset_with_permission_classes_is_fine(check):
    code = """
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def destroy(self, request, pk=None):
        Order.objects.get(pk=pk).delete()
"""
    assert check(code, name="views.py") == []


def test_nextjs_route_handler_without_a_session_check(tmp_path):
    write_tree(
        tmp_path,
        {
            "package.json": '{"dependencies": {"next": "15.0.0"}}',
            "app/api/users/[id]/route.ts": """
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await db.user.delete({ where: { id: params.id } });
  return Response.json({ deleted: true });
}

export async function GET() {
  return Response.json(await db.user.findMany());
}
""",
        },
    )
    assert rules(scan(tmp_path).findings) == [(DESTRUCTIVE, 1)]


def test_nextjs_middleware_matcher_covers_the_route(tmp_path):
    write_tree(
        tmp_path,
        {
            "package.json": '{"dependencies": {"next": "15.0.0"}}',
            "middleware.ts": "export { auth as middleware } from './auth';\n"
            "export const config = { matcher: ['/api/users/:path*'] };\n",
            "app/api/users/[id]/route.ts": "export async function DELETE() { await drop(); }\n",
        },
    )
    assert scan(tmp_path).findings == []


def test_nestjs_guards_and_public_routes(check):
    code = """
import { Controller, Delete, Get, UseGuards } from "@nestjs/common";

@Controller("users")
export class UsersController {
  @Delete(":id")
  remove() {}

  @UseGuards(JwtAuthGuard)
  @Delete("me")
  removeMe() {}

  @Public()
  @Get()
  list() {}
}
"""
    assert rules(check(code, name="users.controller.ts")) == [(DESTRUCTIVE, 6)]


def test_one_finding_per_route_when_both_rules_match(check):
    found = check(FASTAPI + '\n@router.delete("/d")\ndef delete_d(): ...\n')
    assert rules(found) == [(UNPROTECTED, 14)]
