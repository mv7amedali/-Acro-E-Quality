import os, sqlite3, secrets
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, redirect, url_for, session, flash, render_template, abort, g

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("ACRO_DB", os.path.join(APP_DIR, "acro_equality.db"))
UPLOAD_DIR = os.environ.get("ACRO_UPLOADS", os.path.join(APP_DIR, "uploads"))

app = Flask(__name__)
app.secret_key = os.environ.get("ACRO_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
)
os.makedirs(UPLOAD_DIR, exist_ok=True)

ROLES = {
    "owner": "System Owner",
    "admin": "System Admin",
    "manager": "Quality Manager",
    "engineer": "Quality Engineer",
    "supervisor": "Quality Supervisor",
    "inspector": "Quality Inspector",
    "department": "Department Engineer",
}
DEPARTMENTS = [
    "مصنع 1", "مصنع 2", "مصنع 3", "مصنع 4", "مصنع 5", "مصنع 6",
    "المقلوظات", "الجلفنة", "الدهان", "الأجزاء المكملة"
]
STATUSES = [
    "New", "Pending Supervisor Approval", "Pending Quality Approval",
    "Sent to Department", "Responded", "Under Inspection",
    "Rework Required", "Closed"
]

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      full_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      department TEXT,
      manager_id INTEGER,
      supervisor_id INTEGER,
      active INTEGER NOT NULL DEFAULT 1,
      FOREIGN KEY(manager_id) REFERENCES users(id),
      FOREIGN KEY(supervisor_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS memos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      memo_no TEXT UNIQUE NOT NULL,
      created_at TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      owner_engineer_id INTEGER,
      owner_supervisor_id INTEGER,
      department TEXT NOT NULL,
      product_ref TEXT,
      defect_type TEXT NOT NULL,
      location TEXT,
      severity TEXT NOT NULL,
      description TEXT NOT NULL,
      status TEXT NOT NULL,
      supervisor_approved_by INTEGER,
      supervisor_approved_at TEXT,
      quality_approved_by INTEGER,
      quality_approved_at TEXT,
      department_response TEXT,
      department_responded_by INTEGER,
      department_responded_at TEXT,
      inspection_note TEXT,
      closed_by INTEGER,
      closed_at TEXT,
      FOREIGN KEY(created_by) REFERENCES users(id),
      FOREIGN KEY(owner_engineer_id) REFERENCES users(id),
      FOREIGN KEY(owner_supervisor_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      memo_id INTEGER NOT NULL,
      actor_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      details TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY(memo_id) REFERENCES memos(id),
      FOREIGN KEY(actor_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS attachments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      memo_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      uploaded_by INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(memo_id) REFERENCES memos(id),
      FOREIGN KEY(uploaded_by) REFERENCES users(id)
    );
    """)
    conn.commit()
    conn.close()

def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")

def current_user():
    if "user_id" not in session:
        return None
    return db().execute("SELECT * FROM users WHERE id=? AND active=1", (session["user_id"],)).fetchone()

@app.before_request
def load_user():
    g.user = current_user()
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)

@app.context_processor
def inject_globals():
    return {"user": getattr(g, "user", None), "csrf": session.get("csrf"), "roles": ROLES, "departments": DEPARTMENTS}

def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def require_roles(*roles):
    def deco(fn):
        @wraps(fn)
        @require_login
        def wrapper(*args, **kwargs):
            if g.user["role"] == "owner" and "admin" in roles:
                return fn(*args, **kwargs)
            if g.user["role"] not in roles:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return deco

def check_csrf():
    if request.form.get("csrf") != session.get("csrf"):
        abort(400, "Invalid request token")

def audit(memo_id, action, details=""):
    db().execute(
        "INSERT INTO audit(memo_id,actor_id,action,details,created_at) VALUES(?,?,?,?,?)",
        (memo_id, g.user["id"], action, details, now())
    )
    db().commit()

def visible_memos():
    u = g.user
    sql = """SELECT m.*, c.full_name AS creator_name
             FROM memos m JOIN users c ON c.id=m.created_by"""
    if u["role"] in ("manager", "admin", "owner"):
        return db().execute(sql + " ORDER BY m.id DESC").fetchall()
    if u["role"] == "inspector":
        return db().execute(sql + " WHERE m.created_by=? ORDER BY m.id DESC", (u["id"],)).fetchall()
    if u["role"] == "engineer":
        return db().execute(sql + " WHERE m.owner_engineer_id=? ORDER BY m.id DESC", (u["id"],)).fetchall()
    if u["role"] == "supervisor":
        return db().execute(sql + " WHERE m.owner_supervisor_id=? ORDER BY m.id DESC", (u["id"],)).fetchall()
    if u["role"] == "department":
        return db().execute(sql + " WHERE m.department=? ORDER BY m.id DESC", (u["department"],)).fetchall()
    return []

def can_view(m):
    return any(x["id"] == m["id"] for x in visible_memos())

@app.route("/manifest.webmanifest")
def manifest_alias():
    from flask import send_from_directory
    return send_from_directory(os.path.join(APP_DIR, "static"), "manifest.webmanifest")

@app.route("/sw.js")
def service_worker():
    from flask import send_from_directory
    response = send_from_directory(os.path.join(APP_DIR, "static"), "sw.js")
    response.headers["Service-Worker-Allowed"] = "/"
    return response

@app.route("/")
def index():
    if not g.user:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        check_csrf()
        u = db().execute("SELECT * FROM users WHERE username=? AND active=1", (request.form.get("username","").strip(),)).fetchone()
        if u and check_password_hash(u["password_hash"], request.form.get("password","")):
            session.clear()
            session["user_id"] = u["id"]
            session["csrf"] = secrets.token_urlsafe(24)
            return redirect(url_for("dashboard"))
        flash("اسم المستخدم أو كلمة المرور غير صحيحة.")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@require_login
def logout():
    check_csrf()
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@require_login
def dashboard():
    memos = visible_memos()
    counts = {s: sum(1 for m in memos if m["status"] == s) for s in STATUSES}
    return render_template("dashboard.html", memos=memos[:12], counts=counts, total=len(memos), statuses=STATUSES)

@app.route("/memos/new", methods=["GET", "POST"])
@require_roles("inspector", "manager", "admin")
def new_memo():
    if request.method == "POST":
        check_csrf()
        department = request.form.get("department")
        if department not in DEPARTMENTS:
            abort(400, "Invalid department")
        owner_engineer_id = request.form.get("owner_engineer_id") or None
        owner_supervisor_id = request.form.get("owner_supervisor_id") or None
        if not owner_engineer_id or not owner_supervisor_id:
            flash("لازم تحدد مهندس الجودة ومشرف الجودة المسؤولين.")
            return redirect(url_for("new_memo"))
        eng = db().execute("SELECT id FROM users WHERE id=? AND role='engineer' AND active=1", (owner_engineer_id,)).fetchone()
        sup = db().execute("SELECT id FROM users WHERE id=? AND role='supervisor' AND active=1", (owner_supervisor_id,)).fetchone()
        if not eng or not sup:
            abort(400, "Invalid quality chain")
        cur = db().execute("""
          INSERT INTO memos(memo_no,created_at,created_by,owner_engineer_id,owner_supervisor_id,
          department,product_ref,defect_type,location,severity,description,status)
          VALUES('PENDING',?,?,?,?,?,?,?,?,?,?,?)
        """, (now(), g.user["id"], int(owner_engineer_id), int(owner_supervisor_id),
              department, request.form.get("product_ref","").strip(),
              request.form.get("defect_type","").strip(), request.form.get("location","").strip(),
              request.form.get("severity","Medium"), request.form.get("description","").strip(),
              "Pending Supervisor Approval"))
        memo_id = cur.lastrowid
        memo_no = f"ACRO-{memo_id:05d}"
        db().execute("UPDATE memos SET memo_no=? WHERE id=?", (memo_no, memo_id))
        audit(memo_id, "Created", "Memo created and submitted for supervisor approval.")
        db().commit()
        flash(f"تم إنشاء المذكرة {memo_no}.")
        return redirect(url_for("memo_detail", memo_id=memo_id))
    engineers = db().execute("SELECT id,full_name FROM users WHERE role='engineer' AND active=1 ORDER BY full_name").fetchall()
    supervisors = db().execute("SELECT id,full_name FROM users WHERE role='supervisor' AND active=1 ORDER BY full_name").fetchall()
    return render_template("new_memo.html", engineers=engineers, supervisors=supervisors)

@app.route("/memos")
@require_login
def memo_list():
    return render_template("memos.html", memos=visible_memos())

def get_memo(memo_id):
    m = db().execute("SELECT * FROM memos WHERE id=?", (memo_id,)).fetchone()
    if not m or not can_view(m):
        abort(404)
    return m

@app.route("/memos/<int:memo_id>")
@require_login
def memo_detail(memo_id):
    m = get_memo(memo_id)
    audit_rows = db().execute("""SELECT a.*,u.full_name FROM audit a JOIN users u ON u.id=a.actor_id
                                WHERE memo_id=? ORDER BY a.id DESC""", (memo_id,)).fetchall()
    files = db().execute("SELECT * FROM attachments WHERE memo_id=? ORDER BY id", (memo_id,)).fetchall()
    return render_template("memo_detail.html", memo=m, audit_rows=audit_rows, files=files)

@app.route("/memos/<int:memo_id>/approve-supervisor", methods=["POST"])
@require_roles("supervisor", "manager", "admin")
def approve_supervisor(memo_id):
    check_csrf(); m=get_memo(memo_id)
    if g.user["role"] == "supervisor" and m["owner_supervisor_id"] != g.user["id"]: abort(403)
    if m["status"] != "Pending Supervisor Approval": abort(400)
    db().execute("UPDATE memos SET supervisor_approved_by=?,supervisor_approved_at=?,status='Pending Quality Approval' WHERE id=?",
                 (g.user["id"], now(), memo_id))
    db().commit(); audit(memo_id, "Supervisor Approved")
    flash("تم اعتماد المشرف."); return redirect(url_for("memo_detail", memo_id=memo_id))

@app.route("/memos/<int:memo_id>/approve-quality", methods=["POST"])
@require_roles("engineer", "manager", "admin")
def approve_quality(memo_id):
    check_csrf(); m=get_memo(memo_id)
    if g.user["role"] == "engineer" and m["owner_engineer_id"] != g.user["id"]: abort(403)
    if m["status"] != "Pending Quality Approval": abort(400)
    db().execute("UPDATE memos SET quality_approved_by=?,quality_approved_at=?,status='Sent to Department' WHERE id=?",
                 (g.user["id"], now(), memo_id))
    db().commit(); audit(memo_id, "Quality Engineer Approved and Sent to Department")
    flash("تم اعتماد مهندس الجودة وإرسال المذكرة للقسم."); return redirect(url_for("memo_detail", memo_id=memo_id))

@app.route("/memos/<int:memo_id>/respond", methods=["POST"])
@require_roles("department", "manager", "admin")
def respond(memo_id):
    check_csrf(); m=get_memo(memo_id)
    if g.user["role"] == "department" and m["department"] != g.user["department"]: abort(403)
    if m["status"] not in ("Sent to Department", "Rework Required"): abort(400)
    response = request.form.get("department_response","").strip()
    if not response: abort(400, "Response is required")
    db().execute("""UPDATE memos SET department_response=?,department_responded_by=?,department_responded_at=?,
                    status='Responded' WHERE id=?""", (response,g.user["id"],now(),memo_id))
    db().commit(); audit(memo_id, "Department Response", response)
    flash("تم تسجيل رد القسم."); return redirect(url_for("memo_detail", memo_id=memo_id))

@app.route("/memos/<int:memo_id>/inspect", methods=["POST"])
@require_roles("inspector", "engineer", "supervisor", "manager", "admin")
def inspect(memo_id):
    check_csrf(); m=get_memo(memo_id)
    if m["status"] != "Responded": abort(400)
    note=request.form.get("inspection_note","").strip()
    decision=request.form.get("decision")
    if not note: abort(400, "Inspection note is required")
    if decision == "accept":
        db().execute("UPDATE memos SET inspection_note=?,status='Closed',closed_by=?,closed_at=? WHERE id=?",
                     (note,g.user["id"],now(),memo_id))
        db().commit(); audit(memo_id,"Accepted and Closed",note); flash("تم قبول التصحيح وإغلاق المذكرة.")
    elif decision == "rework":
        db().execute("UPDATE memos SET inspection_note=?,status='Rework Required' WHERE id=?", (note,memo_id))
        db().commit(); audit(memo_id,"Rework Required",note); flash("تم إرجاع المذكرة للقسم لاستكمال التصحيح.")
    else: abort(400)
    return redirect(url_for("memo_detail", memo_id=memo_id))

@app.route("/memos/<int:memo_id>/upload", methods=["POST"])
@require_login
def upload(memo_id):
    check_csrf(); m=get_memo(memo_id)
    f=request.files.get("attachment")
    if not f or not f.filename: abort(400)
    ext=os.path.splitext(f.filename)[1].lower()
    if ext not in (".png",".jpg",".jpeg",".pdf"): abort(400,"Only PNG/JPG/PDF files are allowed")
    stored=secrets.token_hex(16)+ext
    f.save(os.path.join(UPLOAD_DIR,stored))
    db().execute("INSERT INTO attachments(memo_id,filename,stored_name,uploaded_by,created_at) VALUES(?,?,?,?,?)",
                 (memo_id, f.filename, stored, g.user["id"], now()))
    db().commit(); audit(memo_id,"Attachment Uploaded",f.filename)
    flash("تم رفع المرفق."); return redirect(url_for("memo_detail", memo_id=memo_id))

@app.route("/attachments/<int:file_id>")
@require_login
def download_attachment(file_id):
    from flask import send_from_directory
    row=db().execute("SELECT * FROM attachments WHERE id=?", (file_id,)).fetchone()
    if not row: abort(404)
    get_memo(row["memo_id"])
    return send_from_directory(UPLOAD_DIR,row["stored_name"],as_attachment=True,download_name=row["filename"])

@app.route("/admin/users", methods=["GET","POST"])
@require_roles("admin")
def users_admin():
    if request.method=="POST":
        check_csrf()
        username=request.form.get("username","").strip()
        full_name=request.form.get("full_name","").strip()
        password=request.form.get("password","")
        role=request.form.get("role","")
        dept=request.form.get("department") or None
        manager_id=request.form.get("manager_id") or None
        supervisor_id=request.form.get("supervisor_id") or None
        if not username or not full_name or len(password)<12 or role not in ROLES or role == "owner":
            flash("راجع البيانات: كلمة المرور يجب أن تكون 12 حرفًا على الأقل.")
            return redirect(url_for("users_admin"))
        if role=="department" and dept not in DEPARTMENTS: abort(400)
        try:
            db().execute("""INSERT INTO users(username,full_name,password_hash,role,department,manager_id,supervisor_id)
                          VALUES(?,?,?,?,?,?,?)""",
                         (username,full_name,generate_password_hash(password),role,dept,manager_id,supervisor_id))
            db().commit(); flash("تم إنشاء المستخدم.")
        except sqlite3.IntegrityError:
            flash("اسم المستخدم مستخدم بالفعل.")
        return redirect(url_for("users_admin"))
    users=db().execute("SELECT id,username,full_name,role,department,active FROM users ORDER BY id").fetchall()
    return render_template("users.html", users=users)

@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@require_roles("admin")
def toggle_user(user_id):
    check_csrf()
    if user_id==g.user["id"]: abort(400)
    db().execute("UPDATE users SET active=1-active WHERE id=?", (user_id,))
    db().commit(); return redirect(url_for("users_admin"))

@app.route("/reports")
@require_roles("manager","admin")
def reports():
    rows=db().execute("""SELECT department,COUNT(*) total,
       SUM(CASE WHEN status='Closed' THEN 1 ELSE 0 END) closed,
       SUM(CASE WHEN status NOT IN ('Closed') THEN 1 ELSE 0 END) open_count
       FROM memos GROUP BY department ORDER BY department""").fetchall()
    return render_template("reports.html", rows=rows)

@app.errorhandler(403)
def forbidden(e): return render_template("error.html", code=403, message="ليس لديك صلاحية للوصول إلى هذه الصفحة."),403
@app.errorhandler(404)
def not_found(e): return render_template("error.html", code=404, message="المذكرة أو الصفحة غير موجودة."),404

def bootstrap_application():
    """Initialize the database and optionally create the first admin user."""
    init_db()
    if os.environ.get("ACRO_BOOTSTRAP_ADMIN") == "1":
        with app.app_context():
            if not db().execute("SELECT id FROM users WHERE role='owner' LIMIT 1").fetchone():
                uname = os.environ.get("ACRO_ADMIN_USER", "owner")
                pwd = os.environ.get("ACRO_ADMIN_PASSWORD", "")
                if len(pwd) < 12:
                    raise RuntimeError("Set ACRO_ADMIN_PASSWORD to a strong password of at least 12 characters.")
                db().execute(
                    "INSERT INTO users(username,full_name,password_hash,role) VALUES(?,?,?,'owner')",
                    (uname, "System Owner", generate_password_hash(pwd)),
                )
                db().commit()

bootstrap_application()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
