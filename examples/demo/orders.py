"""A small FastAPI app with bugs planted on purpose. Run: silentbug-lite examples/demo"""

import logging

from fastapi import APIRouter, Depends

from .auth import get_current_user
from .db import db, mark_order_paid

router = APIRouter()


@router.get("/orders")
def list_orders(status: str, user=Depends(get_current_user)):
    return db.execute(f"SELECT * FROM orders WHERE owner = {user.id} AND status = '{status}'")


@router.get("/orders/{order_id}")
def get_order(order_id: int, user=Depends(get_current_user)):
    return db.execute("SELECT * FROM orders WHERE id = %s", (order_id,))


@router.post("/orders")
def create_order(body: dict, user=Depends(get_current_user)):
    return db.insert("orders", body)


@router.delete("/orders/{order_id}")
def delete_order(order_id: int):
    db.execute("DELETE FROM orders WHERE id = %s", (order_id,))


@router.post("/webhooks/payment")
def payment_webhook(payload: dict):
    try:
        mark_order_paid(payload["order_id"])
        return {"status": "ok"}
    except Exception as e:
        logging.error("payment failed: %s", e)
        return {"status": "success"}
