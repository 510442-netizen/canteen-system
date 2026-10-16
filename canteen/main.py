import json
import os
import re
import sqlite3
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

# ------------------------------------------------------------------
# 1. 絕對路徑與安全環境設定
# ------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DB_NAME = str(BASE_DIR / "canteen.db")
STATIC_DIR = BASE_DIR / "static"
BACKUP_DIR = BASE_DIR / "backups"

# 確保目錄存在
STATIC_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")
if not ADMIN_TOKEN or not ADMIN_TOKEN.strip():
    raise RuntimeError(
        "【資安啟動失敗】未設定 ADMIN_TOKEN 環境變數！\n"
        "請設定環境變數後啟動 (Linux/macOS): export ADMIN_TOKEN='your_secure_password_here'\n"
        "Windows PowerShell: $env:ADMIN_TOKEN='your_secure_password_here'"
    )

app = FastAPI(title="園遊會線上點餐系統 (實機營運正式版)")

# CORS 設定解析
raw_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
ALLOWED_ORIGINS = [o.strip() for o in raw_origins if o.strip()]

if ALLOWED_ORIGINS and ALLOWED_ORIGINS != ["*"]:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
    )

TAIPEI_TZ = ZoneInfo("Asia/Taipei")

# ------------------------------------------------------------------
# 2. 輔助函式、安全回滾與 Rate Limiter
# ------------------------------------------------------------------
def get_taiwan_now() -> datetime:
    return datetime.now(TAIPEI_TZ)

def get_taiwan_today_str() -> str:
    return get_taiwan_now().strftime("%Y-%m-%d")

def get_taiwan_now_str() -> str:
    return get_taiwan_now().strftime("%Y-%m-%d %H:%M:%S")

def safe_rollback(conn):
    try:
        if conn and conn.in_transaction:
            conn.rollback()
    except Exception:
        pass

def is_valid_admin(x_admin_token: Optional[str]) -> bool:
    return bool(x_admin_token and x_admin_token == ADMIN_TOKEN)

ADMIN_FAILED_ATTEMPTS = {}  # ip -> (count, lock_until)

def verify_admin(request: Request, x_admin_token: Optional[str] = Header(None)):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    if client_ip in ADMIN_FAILED_ATTEMPTS:
        count, lock_until = ADMIN_FAILED_ATTEMPTS[client_ip]
        if now < lock_until and count >= 5:
            raise HTTPException(status_code=429, detail="管理者驗證失敗次數過多，請於 1 分鐘後再試")
        elif now >= lock_until:
            ADMIN_FAILED_ATTEMPTS.pop(client_ip, None)

    if not is_valid_admin(x_admin_token):
        count, lock_until = ADMIN_FAILED_ATTEMPTS.get(client_ip, (0, now + 60))
        ADMIN_FAILED_ATTEMPTS[client_ip] = (count + 1, lock_until)
        raise HTTPException(status_code=401, detail="管理者驗證失敗，無存取權限")

    ADMIN_FAILED_ATTEMPTS.pop(client_ip, None)

def sanitize_order_for_customer(order: dict, include_token: bool = False) -> dict:
    items = json.loads(order["items_json"]) if isinstance(order["items_json"], str) else order["items_json"]
    res = {
        "order_id": order["id"],
        "order_number": order["order_number"],
        "customer_name": order["customer_name"],
        "phone_suffix": order["phone_suffix"],
        "items": items,
        "total_price": order["total_price"],
        "total_points": order["total_points"],
        "status": order["status"],
        "created_at": order["created_at"]
    }
    if include_token and "order_token" in order:
        res["order_token"] = order["order_token"]
    return res

def verify_idempotent_match_or_raise(existing_order: dict, req_name: str, req_phone: str, req_item_qty_map: dict):
    if existing_order["customer_name"].strip() != req_name.strip() or existing_order["phone_suffix"].strip() != req_phone.strip():
        raise HTTPException(status_code=409, detail="Idempotency key 衝突：相同 Key 曾用於不同的顧客姓名或電話")

    existing_items = json.loads(existing_order["items_json"]) if isinstance(existing_order["items_json"], str) else existing_order["items_json"]
    existing_map = {i["item_id"]: i["quantity"] for i in existing_items}

    if existing_map != req_item_qty_map:
        raise HTTPException(status_code=409, detail="Idempotency key 衝突：相同 Key 曾用於不同的點餐內容")

# ------------------------------------------------------------------
# 3. 資料庫初始化與無瑕 Migration
# ------------------------------------------------------------------
def get_db(timeout=10.0):
    conn = sqlite3.connect(DB_NAME, timeout=timeout, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn

def db_query(query: str, args=(), one=False):
    conn = get_db()
    try:
        cursor = conn.execute(query, args)
        rows = cursor.fetchall()
        if not rows:
            return None if one else []
        res = [dict(r) for r in rows]
        return res[0] if one else res
    finally:
        conn.close()

def init_db():
    conn = get_db()
    try:
        conn.execute("BEGIN TRANSACTION")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price INTEGER NOT NULL CHECK(price >= 0),
                points INTEGER NOT NULL CHECK(points >= 0),
                is_available INTEGER DEFAULT 1
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_number TEXT NOT NULL,
                order_token TEXT NOT NULL DEFAULT '',
                idempotency_key TEXT NOT NULL DEFAULT '',
                customer_name TEXT NOT NULL,
                phone_suffix TEXT NOT NULL,
                items_json TEXT NOT NULL,
                total_price INTEGER NOT NULL DEFAULT 0,
                total_points INTEGER NOT NULL DEFAULT 0,
                status TEXT DEFAULT 'PENDING',
                created_at TEXT NOT NULL DEFAULT ''
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS daily_counters (
                date_str TEXT PRIMARY KEY,
                last_num INTEGER DEFAULT 0
            );
        """)

        cursor = conn.execute("PRAGMA table_info(orders)")
        existing_cols = {row["name"] for row in cursor.fetchall()}

        if "order_token" not in existing_cols:
            conn.execute("ALTER TABLE orders ADD COLUMN order_token TEXT NOT NULL DEFAULT ''")
        if "idempotency_key" not in existing_cols:
            conn.execute("ALTER TABLE orders ADD COLUMN idempotency_key TEXT NOT NULL DEFAULT ''")
        if "total_price" not in existing_cols:
            conn.execute("ALTER TABLE orders ADD COLUMN total_price INTEGER NOT NULL DEFAULT 0")
        if "total_points" not in existing_cols:
            conn.execute("ALTER TABLE orders ADD COLUMN total_points INTEGER NOT NULL DEFAULT 0")
        if "created_at" not in existing_cols:
            conn.execute("ALTER TABLE orders ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")

        all_orders = conn.execute("SELECT id, order_number, order_token, idempotency_key, created_at FROM orders").fetchall()
        
        seen_tokens = set()
        seen_idem_keys = set()
        max_counters = {}

        for o in all_orders:
            oid = o["id"]
            order_num_str = o["order_number"]
            token = o["order_token"]
            idem = o["idempotency_key"]
            created_at = o["created_at"]

            updates = []
            args = []

            if not token or token in seen_tokens:
                new_token = uuid.uuid4().hex
                while new_token in seen_tokens:
                    new_token = uuid.uuid4().hex
                token = new_token
                updates.append("order_token = ?")
                args.append(token)
            seen_tokens.add(token)

            if not idem:
                new_idem = f"migrated_empty_{uuid.uuid4().hex}"
                while new_idem in seen_idem_keys:
                    new_idem = f"migrated_empty_{uuid.uuid4().hex}"
                idem = new_idem
                updates.append("idempotency_key = ?")
                args.append(idem)
            elif idem in seen_idem_keys:
                new_idem = f"migrated_dup_{uuid.uuid4().hex}"
                while new_idem in seen_idem_keys:
                    new_idem = f"migrated_dup_{uuid.uuid4().hex}"
                idem = new_idem
                updates.append("idempotency_key = ?")
                args.append(idem)
            seen_idem_keys.add(idem)

            if not created_at:
                created_at = get_taiwan_now_str()
                updates.append("created_at = ?")
                args.append(created_at)

            if created_at and order_num_str and order_num_str.startswith("A"):
                date_part = created_at.split()[0] if ' ' in created_at else created_at[:10]
                num_part = order_num_str[1:]
                if num_part.isdigit():
                    num_val = int(num_part)
                    if date_part not in max_counters or num_val > max_counters[date_part]:
                        max_counters[date_part] = num_val

            if updates:
                args.append(oid)
                conn.execute(f"UPDATE orders SET {', '.join(updates)} WHERE id = ?", args)

        for d_str, m_num in max_counters.items():
            conn.execute("""
                INSERT INTO daily_counters (date_str, last_num) VALUES (?, ?)
                ON CONFLICT(date_str) DO UPDATE SET last_num = MAX(last_num, excluded.last_num)
            """, (d_str, m_num))

        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_order_token ON orders(order_token) WHERE order_token != ''")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_orders_idempotency_key ON orders(idempotency_key) WHERE idempotency_key != ''")

        if conn.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO items (name, price, points, is_available) VALUES (?, ?, ?, 1)",
                [
                    ("招牌炸雞塊", 60, 60),
                    ("冰香濃紅茶", 30, 30),
                    ("超值炸雞套餐 (雞塊+紅茶)", 80, 75),
                    ("手工起司餅", 45, 45)
                ]
            )

        conn.execute("COMMIT")
    except Exception as e:
        safe_rollback(conn)
        raise RuntimeError(f"資料庫初始化與遷移失敗: {str(e)}")
    finally:
        conn.close()

init_db()

# ------------------------------------------------------------------
# 4. Pydantic 驗證模型
# ------------------------------------------------------------------
class OrderItemInput(BaseModel):
    item_id: int
    quantity: int = Field(..., gt=0, le=50)

class CreateOrderRequest(BaseModel):
    idempotency_key: str = Field(..., min_length=10, max_length=64)
    customer_name: str
    phone_suffix: str
    items: List[OrderItemInput] = Field(..., min_items=1, max_items=20)

    @field_validator("customer_name")
    @classmethod
    def validate_customer_name(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("顧客姓名不可為空白")
        if len(s) > 20:
            raise ValueError("姓名長度不可超過 20 個字")
        return s

    @field_validator("phone_suffix")
    @classmethod
    def validate_phone_suffix(cls, v: str) -> str:
        s = v.strip()
        if not re.match(r"^\d{3,4}$", s):
            raise ValueError("電話末碼必須為 3 至 4 位數字")
        return s

ALLOWED_STATUSES = {"PENDING", "IN_PROGRESS", "READY", "COMPLETED", "CANCELLED"}

class StatusUpdateRequest(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        if v not in ALLOWED_STATUSES:
            raise ValueError(f"不合法的狀態標籤，允許值為：{', '.join(ALLOWED_STATUSES)}")
        return v

# ------------------------------------------------------------------
# 5. API 端點
# ------------------------------------------------------------------
@app.get("/api/items")
def get_public_items():
    items = db_query("SELECT id, name, price, points, is_available FROM items WHERE is_available = 1")
    for item in items:
        item["is_available"] = bool(item["is_available"])
    return items

@app.get("/api/admin/items", dependencies=[Depends(verify_admin)])
def get_admin_items():
    items = db_query("SELECT id, name, price, points, is_available FROM items")
    for item in items:
        item["is_available"] = bool(item["is_available"])
    return items

@app.patch("/api/items/{item_id}/toggle", dependencies=[Depends(verify_admin)])
def toggle_item_status(item_id: int):
    conn = get_db(timeout=5.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        item = conn.execute("SELECT is_available FROM items WHERE id = ?", (item_id,)).fetchone()
        if not item:
            safe_rollback(conn)
            raise HTTPException(status_code=404, detail="找不到該商品")
        
        new_status = 0 if item["is_available"] == 1 else 1
        conn.execute("UPDATE items SET is_available = ? WHERE id = ?", (new_status, item_id))
        conn.execute("COMMIT")
        return {"message": "商品狀態更新成功", "is_available": bool(new_status)}
    except Exception as e:
        safe_rollback(conn)
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="商品狀態更新失敗")
    finally:
        conn.close()

@app.post("/api/orders")
def create_order(req: CreateOrderRequest):
    item_qty_map = {}
    for item in req.items:
        item_qty_map[item.item_id] = item_qty_map.get(item.item_id, 0) + item.quantity

    for item_id, total_qty in item_qty_map.items():
        if total_qty > 50:
            raise HTTPException(status_code=400, detail=f"單一餐點總數量不可超過 50 份 (ID: {item_id})")

    existing = db_query("SELECT * FROM orders WHERE idempotency_key = ?", (req.idempotency_key,), one=True)
    if existing:
        verify_idempotent_match_or_raise(existing, req.customer_name, req.phone_suffix, item_qty_map)
        return sanitize_order_for_customer(existing, include_token=True)

    item_ids = list(item_qty_map.keys())
    placeholders = ",".join("?" * len(item_ids))

    max_retries = 3
    for attempt in range(max_retries):
        conn = get_db(timeout=5.0)
        try:
            conn.execute("BEGIN IMMEDIATE")

            dup_check = conn.execute("SELECT * FROM orders WHERE idempotency_key = ?", (req.idempotency_key,)).fetchone()
            if dup_check:
                conn.execute("COMMIT")
                dup_dict = dict(dup_check)
                verify_idempotent_match_or_raise(dup_dict, req.customer_name, req.phone_suffix, item_qty_map)
                return sanitize_order_for_customer(dup_dict, include_token=True)

            db_items = conn.execute(
                f"SELECT id, name, price, points, is_available FROM items WHERE id IN ({placeholders})", 
                item_ids
            ).fetchall()
            
            db_items_dict = {row["id"]: row for row in db_items}

            for item_id in item_ids:
                if item_id not in db_items_dict:
                    raise HTTPException(status_code=400, detail=f"找不到商品 ID: {item_id}")

            disabled_names = [db_items_dict[i]["name"] for i in item_ids if db_items_dict[i]["is_available"] == 0]
            if disabled_names:
                raise HTTPException(status_code=400, detail=f"以下餐點已暫停販售：{', '.join(disabled_names)}")

            order_items_snapshot = []
            total_price = 0
            total_points = 0

            for item_id, qty in item_qty_map.items():
                info = db_items_dict[item_id]
                total_price += info["price"] * qty
                total_points += info["points"] * qty

                order_items_snapshot.append({
                    "item_id": item_id,
                    "name": info["name"],
                    "price": info["price"],
                    "points": info["points"],
                    "quantity": qty
                })

            today_str = get_taiwan_today_str()
            cursor = conn.execute("SELECT last_num FROM daily_counters WHERE date_str = ?", (today_str,))
            row = cursor.fetchone()

            if row:
                next_num = row["last_num"] + 1
                conn.execute("UPDATE daily_counters SET last_num = ? WHERE date_str = ?", (next_num, today_str))
            else:
                next_num = 1
                conn.execute("INSERT INTO daily_counters (date_str, last_num) VALUES (?, ?)", (today_str, next_num))

            order_num = f"A{next_num:02d}"
            order_token = uuid.uuid4().hex

            items_json_str = json.dumps(order_items_snapshot, ensure_ascii=False)
            created_at_str = get_taiwan_now_str()

            cursor = conn.execute(
                """
                INSERT INTO orders (order_number, order_token, idempotency_key, customer_name, phone_suffix, items_json, total_price, total_points, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (order_num, order_token, req.idempotency_key, req.customer_name, req.phone_suffix, items_json_str, total_price, total_points, created_at_str)
            )
            order_id = cursor.lastrowid
            conn.execute("COMMIT")

            new_order = {
                "id": order_id,
                "order_number": order_num,
                "order_token": order_token,
                "customer_name": req.customer_name,
                "phone_suffix": req.phone_suffix,
                "items_json": order_items_snapshot,
                "total_price": total_price,
                "total_points": total_points,
                "status": "PENDING",
                "created_at": created_at_str
            }
            return sanitize_order_for_customer(new_order, include_token=True)

        except sqlite3.IntegrityError:
            safe_rollback(conn)
            dup_dict = db_query("SELECT * FROM orders WHERE idempotency_key = ?", (req.idempotency_key,), one=True)
            if dup_dict:
                verify_idempotent_match_or_raise(dup_dict, req.customer_name, req.phone_suffix, item_qty_map)
                return sanitize_order_for_customer(dup_dict, include_token=True)
            raise HTTPException(status_code=409, detail="Idempotency key 衝突或重複提交，請確認訂單內容")

        except sqlite3.OperationalError as e:
            safe_rollback(conn)
            if "locked" in str(e).lower() or "busy" in str(e).lower():
                if attempt < max_retries - 1:
                    time.sleep(0.1 * (2 ** attempt))
                    continue
            raise HTTPException(status_code=503, detail="系統繁忙（資料庫鎖定），請稍後再試")
        except Exception as e:
            safe_rollback(conn)
            if isinstance(e, HTTPException):
                raise e
            raise HTTPException(status_code=500, detail=f"下單處理失敗: {str(e)}")
        finally:
            conn.close()

@app.get("/api/orders")
def get_orders(
    request: Request,
    order_id: Optional[int] = Query(None),
    token: Optional[str] = Query(None),
    x_admin_token: Optional[str] = Header(None)
):
    if order_id is not None:
        order = db_query("SELECT * FROM orders WHERE id = ?", (order_id,), one=True)
        if not order:
            raise HTTPException(status_code=404, detail="找不到該筆訂單")

        is_admin = is_valid_admin(x_admin_token)
        is_owner = (token and token == order["order_token"])

        if not (is_admin or is_owner):
            raise HTTPException(status_code=403, detail="無權限檢視此訂單資訊 (查詢憑證無效)")

        return sanitize_order_for_customer(order, include_token=False)
    
    verify_admin(request, x_admin_token)
        
    orders = db_query("SELECT * FROM orders ORDER BY id DESC")
    return [sanitize_order_for_customer(o, include_token=False) for o in orders]

@app.patch("/api/orders/{order_id}/status", dependencies=[Depends(verify_admin)])
def update_order_status(order_id: int, req: StatusUpdateRequest):
    conn = get_db()
    try:
        conn.execute("BEGIN TRANSACTION")
        cursor = conn.execute("UPDATE orders SET status = ? WHERE id = ?", (req.status, order_id))
        if cursor.rowcount == 0:
            safe_rollback(conn)
            raise HTTPException(status_code=404, detail="找不到該筆訂單")
        conn.execute("COMMIT")
    except Exception as e:
        safe_rollback(conn)
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="更新訂單狀態失敗")
    finally:
        conn.close()
    return {"message": "訂單狀態更新成功", "status": req.status}

@app.post("/api/admin/backup", dependencies=[Depends(verify_admin)])
def backup_database():
    timestamp = get_taiwan_now().strftime("%Y%m%d_%H%M%S")
    backup_file = BACKUP_DIR / f"canteen_backup_{timestamp}.db"
    
    src_conn = get_db()
    dst_conn = sqlite3.connect(str(backup_file))
    try:
        src_conn.backup(dst_conn)
        return {"message": "資料庫備份成功", "file": backup_file.name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"備份失敗: {str(e)}")
    finally:
        dst_conn.close()
        src_conn.close()

# ------------------------------------------------------------------
# 6. 安全掛載靜態網頁 (僅限 static 目錄，絕不暴露根目錄/DB)
# ------------------------------------------------------------------
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)