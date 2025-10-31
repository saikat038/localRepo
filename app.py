
# import os, json
# from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
# from datetime import datetime, timedelta
# from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
# from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import generate_password_hash, check_password_hash

# # -----------------------------
# # Helpers: DATABASE_URL normalize (sslmode=require for Postgres)
# # -----------------------------
# def normalize_database_url(raw: str) -> str:
#     """
#     Ensure SQLAlchemy-compatible URL and enforce sslmode=require for Postgres.
#     Accepts postgres:// or postgresql://; adds ?sslmode=require if missing.
#     """
#     if not raw:
#         return "sqlite:///data/app.db"
#     url = raw.replace("postgres://", "postgresql://", 1)
#     parsed = urlparse(url)
#     if parsed.scheme.startswith("postgresql"):
#         qs = parse_qs(parsed.query)
#         if "sslmode" not in qs:
#             qs["sslmode"] = ["require"]
#         new_query = urlencode({k: v[0] for k, v in qs.items()})
#         url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
#     return url

# # -----------------------------
# # Flask App
# # -----------------------------
# def make_app():
#     app = Flask(__name__)
#     app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change")

#     raw_db = os.environ.get("DATABASE_URL", "sqlite:///data/app.db")
#     app.config["SQLALCHEMY_DATABASE_URI"] = normalize_database_url(raw_db)
#     app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
#     # Optional: pool tuning for Postgres
#     app.config.setdefault("SQLALCHEMY_ENGINE_OPTIONS", {"pool_pre_ping": True})
#     return app

# app = make_app()
# db = SQLAlchemy(app)

# # -----------------------------
# # Models
# # -----------------------------
# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     email = db.Column(db.String(255), unique=True, nullable=False, index=True)
#     name = db.Column(db.String(255), nullable=False, index=True)
#     role = db.Column(db.String(20), nullable=False, default="agent")  # 'admin' or 'agent'
#     password_hash = db.Column(db.String(255), nullable=True)

#     def set_password(self, password: str):
#         self.password_hash = generate_password_hash(password)

#     def check_password(self, password: str) -> bool:
#         if not self.password_hash:
#             return False
#         return check_password_hash(self.password_hash, password)

# class Lead(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     first_name = db.Column(db.String(120), nullable=False)
#     last_name = db.Column(db.String(120), nullable=True)
#     phone = db.Column(db.String(40), nullable=False, index=True)
#     campaign = db.Column(db.String(40), nullable=False)  # FE / SSDI / ACA-OBAMA
#     campaign_type = db.Column(db.String(40), nullable=False)  # CPL BUFFER / CPA ENROLMENT
#     did = db.Column(db.String(120), nullable=True, index=True)
#     note = db.Column(db.Text, nullable=True)
#     status = db.Column(db.String(20), nullable=False, default="PENDING", index=True)  # PENDING / CONVERSION / REJECTED
#     payout = db.Column(db.Integer, nullable=False, default=0)  # 400 or 700 when status==CONVERSION else 0
#     payment = db.Column(db.String(10), nullable=False, default="NIL", index=True)  # PAID / NIL
#     created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
#     created_by_name = db.Column(db.String(255), nullable=False, index=True)
#     created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

# class Settings(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     google_sheets_spreadsheet_id = db.Column(db.String(200), nullable=True)
#     google_sheets_service_json = db.Column(db.Text, nullable=True)  # store Service Account JSON (keep private)

# # -----------------------------
# # Utilities
# # -----------------------------
# def current_user():
#     uid = session.get("user_id")
#     if not uid:
#         return None
#     return db.session.get(User, uid)

# def login_required(role=None):
#     def decorator(fn):
#         from functools import wraps
#         @wraps(fn)
#         def wrapper(*args, **kwargs):
#             user = current_user()
#             if not user:
#                 return redirect(url_for("login"))
#             if role and user.role != role:
#                 abort(403)
#             return fn(*args, **kwargs)
#         return wrapper
#     return decorator

# def compute_payout(campaign_type: str, status: str) -> int:
#     if status == "CONVERSION":
#         if campaign_type.strip().upper().startswith("CPL"):
#             return 400
#         if campaign_type.strip().upper().startswith("CPA"):
#             return 700
#     return 0

# def ist(dt: datetime) -> datetime:
#     return dt + timedelta(hours=5, minutes=30)

# # -----------------------------
# # Bootstrap DB and initial admin
# # -----------------------------
# with app.app_context():
#     os.makedirs("data", exist_ok=True)
#     db.create_all()
#     if not Settings.query.first():
#         db.session.add(Settings())
#         db.session.commit()
#     admin_email = os.environ.get("ADMIN_EMAIL")
#     admin_name = os.environ.get("ADMIN_NAME", "Admin")
#     admin_password = os.environ.get("ADMIN_PASSWORD")
#     if admin_email and admin_password:
#         admin = User.query.filter_by(email=admin_email).first()
#         if not admin:
#             admin = User(email=admin_email, name=admin_name, role="admin")
#             admin.set_password(admin_password)
#             db.session.add(admin)
#             db.session.commit()

# # -----------------------------
# # Auth
# # -----------------------------
# from flask import jsonify

# @app.route("/login", methods=["GET", "POST"])
# def login():
#     if request.method == "POST":
#         role = request.form.get("role")
#         email = request.form.get("email", "").strip().lower()
#         name = request.form.get("name", "").strip()

#         user = User.query.filter_by(email=email).first()
#         if role == "admin":
#             password = request.form.get("password", "")
#             if user and user.role == "admin" and user.check_password(password):
#                 session["user_id"] = user.id
#                 session["role"] = "admin"
#                 return redirect(url_for("admin_dashboard"))
#             else:
#                 flash("Invalid admin credentials.", "error")
#         else:
#             if user and user.role == "agent" and user.name == name:
#                 session["user_id"] = user.id
#                 session["role"] = "agent"
#                 return redirect(url_for("agent_dashboard"))
#             else:
#                 flash("Agent not authorized. Ask admin to register you.", "error")
#     return render_template("login.html")

# @app.get("/logout")
# def logout():
#     session.clear()
#     return redirect(url_for("login"))

# # -----------------------------
# # Agent
# # -----------------------------
# @app.get("/agent")
# @login_required(role="agent")
# def agent_dashboard():
#     user = current_user()
#     leads = Lead.query.filter_by(created_by_id=user.id).order_by(Lead.created_at.desc()).all()
#     return render_template("agent_dashboard.html", user=user, leads=leads, ist=ist)

# @app.post("/agent/leads")
# @login_required(role="agent")
# def agent_create_lead():
#     user = current_user()
#     first_name = request.form.get("first_name","").strip()
#     last_name = request.form.get("last_name","").strip()
#     phone = request.form.get("phone","").strip()
#     campaign = request.form.get("campaign","").strip()
#     campaign_type = request.form.get("campaign_type","").strip()
#     did = request.form.get("did","").strip()
#     note = request.form.get("note","").strip()
#     status = "PENDING"
#     payout = compute_payout(campaign_type, status)

#     lead = Lead(
#         first_name=first_name, last_name=last_name, phone=phone,
#         campaign=campaign, campaign_type=campaign_type, did=did, note=note,
#         status=status, payout=payout, payment="NIL",
#         created_by_id=user.id, created_by_name=user.name
#     )
#     db.session.add(lead)
#     db.session.commit()
#     flash("Lead submitted.", "success")
#     return redirect(url_for("agent_dashboard"))

# # -----------------------------
# # Admin + Filters
# # -----------------------------
# @app.get("/admin")
# @login_required(role="admin")
# def admin_dashboard():
#     date_from = request.args.get("date_from","").strip()
#     date_to = request.args.get("date_to","").strip()
#     agent_name = request.args.get("agent_name","").strip()
#     type_filter = request.args.get("campaign_type","").strip()  # CPL or CPA
#     did = request.args.get("did","").strip()
#     conversion_only = request.args.get("conversion_only","") == "on"

#     q = Lead.query

#     def parse_date(d):
#         try:
#             return datetime.strptime(d, "%Y-%m-%d")
#         except Exception:
#             return None

#     if date_from:
#         df = parse_date(date_from)
#         if df:
#             q = q.filter(Lead.created_at >= df)
#     if date_to:
#         dt = parse_date(date_to)
#         if dt:
#             q = q.filter(Lead.created_at < dt + timedelta(days=1))

#     if agent_name:
#         q = q.filter(Lead.created_by_name.ilike(f"%{agent_name}%"))
#     if type_filter:
#         tf = type_filter.upper()
#         if tf in ["CPL", "CPA"]:
#             q = q.filter(Lead.campaign_type.ilike(f"{tf}%"))
#         else:
#             q = q.filter(Lead.campaign_type.ilike(f"%{type_filter}%"))
#     if did:
#         q = q.filter(Lead.did.ilike(f"%{did}%"))
#     if conversion_only:
#         q = q.filter(Lead.status == "CONVERSION")

#     leads = q.order_by(Lead.created_at.desc()).all()
#     unpaid = db.session.query(db.func.sum(Lead.payout)).filter(Lead.status=="CONVERSION", Lead.payment=="NIL").scalar() or 0
#     agents = User.query.filter_by(role="agent").order_by(User.name.asc()).all()
#     settings = Settings.query.first()
#     return render_template("admin_dashboard.html",
#                            leads=leads, agents=agents, unpaid_total=unpaid,
#                            date_from=date_from, date_to=date_to, agent_name=agent_name,
#                            type_filter=type_filter, did=did, conversion_only=conversion_only,
#                            settings=settings, ist=ist)

# @app.post("/admin/leads/<int:lead_id>/update")
# @login_required(role="admin")
# def admin_update_lead(lead_id):
#     lead = db.session.get(Lead, lead_id)
#     if not lead:
#         abort(404)
#     lead.first_name = request.form.get("first_name", lead.first_name).strip()
#     lead.last_name = request.form.get("last_name", lead.last_name).strip()
#     lead.phone = request.form.get("phone", lead.phone).strip()
#     lead.campaign = request.form.get("campaign", lead.campaign).strip()
#     lead.campaign_type = request.form.get("campaign_type", lead.campaign_type).strip()
#     lead.did = request.form.get("did", lead.did).strip()
#     lead.note = request.form.get("note", lead.note)
#     lead.status = request.form.get("status", lead.status).strip()
#     lead.payment = request.form.get("payment", lead.payment).strip()
#     lead.payout = compute_payout(lead.campaign_type, lead.status)
#     db.session.commit()
#     flash("Lead updated.", "success")
#     return redirect(url_for("admin_dashboard"))

# @app.post("/admin/agents")
# @login_required(role="admin")
# def admin_add_agent():
#     email = request.form.get("email","").strip().lower()
#     name = request.form.get("name","").strip()
#     if not email or not name:
#         flash("Email and name are required.", "error")
#         return redirect(url_for("admin_dashboard"))
#     existing = User.query.filter_by(email=email).first()
#     if existing:
#         flash("User already exists.", "error")
#         return redirect(url_for("admin_dashboard"))
#     agent = User(email=email, name=name, role="agent")
#     db.session.add(agent)
#     db.session.commit()
#     flash("Agent added.", "success")
#     return redirect(url_for("admin_dashboard"))

# @app.post("/admin/agents/<int:user_id>/delete")
# @login_required(role="admin")
# def admin_delete_agent(user_id):
#     user = db.session.get(User, user_id)
#     if not user or user.role != "agent":
#         abort(404)
#     Lead.query.filter_by(created_by_id=user.id).update({Lead.created_by_name: "[deleted agent]"})
#     db.session.delete(user)
#     db.session.commit()
#     flash("Agent deleted.", "success")
#     return redirect(url_for("admin_dashboard"))

# # -----------------------------
# # Settings (Google Sheets)
# # -----------------------------
# @app.post("/admin/settings")
# @login_required(role="admin")
# def admin_save_settings():
#     sheet_id = request.form.get("google_sheet_id","").strip()
#     svc_json = request.form.get("google_service_json","").strip()
#     st = Settings.query.first()
#     st.google_sheets_spreadsheet_id = sheet_id or None
#     st.google_sheets_service_json = svc_json or None
#     db.session.commit()
#     flash("Backup settings saved.", "success")
#     return redirect(url_for("admin_dashboard"))

# # -----------------------------
# # Export / Backup
# # -----------------------------
# def export_leads_to_csv(csv_path: str):
#     import csv
#     fields = ["id","first_name","last_name","phone","campaign","campaign_type","did","note",
#               "status","payout","payment","created_by_id","created_by_name","created_at"]
#     with open(csv_path, "w", newline="", encoding="utf-8") as f:
#         writer = csv.writer(f)
#         writer.writerow(fields)
#         for lead in Lead.query.order_by(Lead.id.asc()).all():
#             writer.writerow([
#                 lead.id, lead.first_name, lead.last_name, lead.phone, lead.campaign, lead.campaign_type,
#                 lead.did, lead.note, lead.status, lead.payout, lead.payment, lead.created_by_id,
#                 lead.created_by_name, lead.created_at.isoformat()
#             ])
#     return csv_path

# def export_to_google_sheets(settings: Settings):
#     spreadsheet_id = (settings.google_sheets_spreadsheet_id if settings else None) or os.environ.get("GOOGLE_SHEETS_SPREADSHEET_ID")
#     svc_json = (settings.google_sheets_service_json if settings else None) or os.environ.get("GOOGLE_SHEETS_SERVICE_ACCOUNT_JSON")
#     if not svc_json or not spreadsheet_id:
#         return False, "Google Sheets not configured."
#     try:
#         import gspread
#         from google.oauth2.service_account import Credentials
#         scopes = ["https://www.googleapis.com/auth/spreadsheets"]
#         info = json.loads(svc_json)
#         creds = Credentials.from_service_account_info(info, scopes=scopes)
#         client = gspread.authorize(creds)
#         sh = client.open_by_key(spreadsheet_id)
#         try:
#             ws = sh.worksheet("leads")
#             ws.clear()
#         except Exception:
#             ws = sh.add_worksheet(title="leads", rows="1000", cols="20")
#         rows = [["id","first_name","last_name","phone","campaign","campaign_type","did","note",
#                  "status","payout","payment","created_by_id","created_by_name","created_at"]]
#         for lead in Lead.query.order_by(Lead.id.asc()).all():
#             rows.append([
#                 lead.id, lead.first_name, lead.last_name, lead.phone, lead.campaign, lead.campaign_type,
#                 lead.did, lead.note, lead.status, lead.payout, lead.payment, lead.created_by_id,
#                 lead.created_by_name, lead.created_at.isoformat()
#             ])
#         ws.update("A1", rows)
#         return True, "Exported to Google Sheets."
#     except Exception as e:
#         return False, f"Google Sheets export failed: {e}"

# @app.get("/tasks/backup")
# def run_backup():
#     token = request.args.get("token")
#     expected = os.environ.get("BACKUP_TOKEN")
#     if not expected or token != expected:
#         abort(403)
#     os.makedirs("data", exist_ok=True)
#     today = datetime.utcnow().strftime("%Y-%m-%d")
#     csv_path = os.path.join("data", f"leads-{today}.csv")
#     export_leads_to_csv(csv_path)
#     ok, msg = export_to_google_sheets(Settings.query.first())
#     return {"ok": True, "csv": csv_path, "google_sheets": msg if ok else f"Skipped/Failed: {msg}"}

# @app.post("/admin/run-backup-now")
# @login_required(role="admin")
# def run_backup_now():
#     csv_path = os.path.join("data", "leads-manual.csv")
#     export_leads_to_csv(csv_path)
#     ok, msg = export_to_google_sheets(Settings.query.first())
#     flash(f"Backup: CSV saved. Sheets: {msg}", "success" if ok else "error")
#     return redirect(url_for("admin_dashboard"))

# # -----------------------------
# # Health
# # -----------------------------
# @app.get("/api/health")
# def health():
#     return {
#         "ok": True,
#         "service": "perfwise-crm",
#         "version": "1.2.0-pg",
#         "db": str(app.config.get("SQLALCHEMY_DATABASE_URI"))[:80] + "..."
#     }

# # -----------------------------
# # Root + Static
# # -----------------------------
# @app.get("/")
# def index():
#     u = current_user()
#     if not u:
#         return redirect(url_for("login"))
#     return redirect(url_for("admin_dashboard" if u.role=="admin" else "agent_dashboard"))

# @app.route('/data/<path:filename>')
# @login_required(role="admin")
# def download_data(filename):
#     return send_from_directory("data", filename, as_attachment=True)

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))





#######################################################################################
# CRM Software
#######################################################################################
# app.py  — Streamlit CRM (admin/agent) with SQLAlchemy
import os
from datetime import datetime
from typing import Optional

import pandas as pd
import streamlit as st
from sqlalchemy import (
    create_engine, text, Table, Column, Integer, String, DateTime, ForeignKey, MetaData
)
from sqlalchemy.engine import Engine
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- Config ----------
st.set_page_config(page_title="CRM", layout="wide")

def normalize_database_url(raw: str) -> str:
    """Accepts postgres:// or postgresql:// and enforces sslmode=require for PG."""
    if not raw:
        return "sqlite:///crm.db"
    if raw.startswith("postgres://"):
        raw = raw.replace("postgres://", "postgresql://", 1)
    # add sslmode=require if missing (for hosted Postgres)
    if raw.startswith("postgresql://") and "sslmode=" not in raw:
        sep = "&" if "?" in raw else "?"
        raw = f"{raw}{sep}sslmode=require"
    return raw

DATABASE_URL = normalize_database_url(os.environ.get("DATABASE_URL"))
engine: Engine = create_engine(DATABASE_URL, future=True)

# ---------- Schema ----------
meta = MetaData()

users = Table(
    "users", meta,
    Column("id", Integer, primary_key=True),
    Column("email", String(255), unique=True, nullable=False, index=True),
    Column("name", String(255), nullable=False),
    Column("password_hash", String(255), nullable=False),
    Column("role", String(50), nullable=False, default="agent"),  # "admin" | "agent"
    Column("created_at", DateTime, default=datetime.utcnow, nullable=False),
)

contacts = Table(
    "contacts", meta,
    Column("id", Integer, primary_key=True),
    Column("name", String(255), nullable=False),
    Column("email", String(255)),
    Column("company", String(255)),
    Column("phone", String(100)),
    Column("stage", String(50), default="Lead"),
    Column("owner_id", Integer, ForeignKey("users.id")),
    Column("created_at", DateTime, default=datetime.utcnow, nullable=False),
)

def init_db():
    meta.create_all(engine)
    # Seed an admin if none exists
    with engine.begin() as conn:
        have = conn.execute(text("SELECT 1 FROM users WHERE role='admin' LIMIT 1")).first()
        if not have:
            admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
            admin_pass = os.environ.get("ADMIN_PASSWORD", "admin123")
            conn.execute(
                users.insert().values(
                    email=admin_email,
                    name="Admin",
                    role="admin",
                    password_hash=generate_password_hash(admin_pass),
                    created_at=datetime.utcnow(),
                )
            )

init_db()

# ---------- Auth helpers ----------
def authenticate(email: str, password: str) -> Optional[dict]:
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT id, email, name, role, password_hash FROM users WHERE email=:e"),
            {"e": email.strip().lower()},
        ).mappings().first()
        if row and check_password_hash(row["password_hash"], password):
            return dict(row)
    return None

def require_login() -> Optional[dict]:
    if "user" not in st.session_state:
        st.info("Please log in to continue.")
        st.stop()
    return st.session_state["user"]

# ---------- Sidebar ----------
def sidebar_user_box():
    u = st.session_state.get("user")
    if u:
        st.sidebar.success(f"👤 {u['name']} ({u['role']})")
        if st.sidebar.button("Log out"):
            st.session_state.pop("user", None)
            st.rerun()

# ---------- Pages ----------
def page_login():
    st.title("🔐 Login")
    with st.form("login"):
        email = st.text_input("Email", placeholder="you@company.com")
        password = st.text_input("Password", type="password")
        ok = st.form_submit_button("Sign in")
    if ok:
        user = authenticate(email, password)
        if user:
            st.session_state["user"] = user
            st.success("Logged in.")
            st.rerun()
        else:
            st.error("Invalid credentials.")

def page_admin_dashboard():
    user = require_login()
    assert user["role"] == "admin", "Admins only"
    st.title("🛠️ Admin Dashboard")

    tab_users, tab_contacts, tab_upload = st.tabs(["Users", "Contacts", "Import CSV"])
    with tab_users:
        st.subheader("User Management")
        with engine.begin() as conn:
            df = pd.read_sql(text("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC"), conn)
        st.dataframe(df, use_container_width=True)

        with st.expander("➕ Add user"):
            name = st.text_input("Name", key="nu_name")
            email = st.text_input("Email", key="nu_email")
            role = st.selectbox("Role", ["agent", "admin"], key="nu_role")
            pwd = st.text_input("Password", type="password", key="nu_pwd")
            if st.button("Create user"):
                if not (name and email and pwd):
                    st.warning("Fill all required fields.")
                else:
                    try:
                        with engine.begin() as conn:
                            conn.execute(users.insert().values(
                                name=name,
                                email=email.strip().lower(),
                                role=role,
                                password_hash=generate_password_hash(pwd),
                                created_at=datetime.utcnow(),
                            ))
                        st.success("User created.")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed: {e}")

    with tab_contacts:
        st.subheader("All Contacts")
        with engine.begin() as conn:
            cdf = pd.read_sql(text("""
                SELECT c.id, c.name, c.email, c.company, c.phone, c.stage, c.owner_id, c.created_at,
                       u.name AS owner
                FROM contacts c
                LEFT JOIN users u ON u.id = c.owner_id
                ORDER BY c.id DESC
            """), conn)
        st.dataframe(cdf, use_container_width=True)
        st.download_button("⬇️ Export contacts CSV", cdf.to_csv(index=False).encode("utf-8"), "contacts.csv", "text/csv")

    with tab_upload:
        st.subheader("Bulk import contacts (CSV)")
        st.caption("Columns supported: name,email,company,phone,stage,owner_id")
        file = st.file_uploader("Upload CSV", type=["csv"])
        if file and st.button("Import"):
            imp = pd.read_csv(file).fillna("")
            with engine.begin() as conn:
                for _, r in imp.iterrows():
                    conn.execute(contacts.insert().values(
                        name=r.get("name",""),
                        email=r.get("email",""),
                        company=r.get("company",""),
                        phone=r.get("phone",""),
                        stage=r.get("stage","Lead"),
                        owner_id=int(r["owner_id"]) if str(r.get("owner_id","")).isdigit() else None,
                        created_at=datetime.utcnow(),
                    ))
            st.success(f"Imported {len(imp)} contacts.")
            st.rerun()

def page_agent_dashboard():
    user = require_login()
    st.title("📇 Agent Dashboard")
    st.caption("Manage your contacts")

    # Add contact
    with st.form("add_contact", clear_on_submit=True):
        cols = st.columns(5)
        name   = cols[0].text_input("Name*", placeholder="Jane Doe")
        email  = cols[1].text_input("Email")
        company= cols[2].text_input("Company")
        phone  = cols[3].text_input("Phone")
        stage  = cols[4].selectbox("Stage", ["Lead","Qualified","Proposal","Won","Lost"])
        add_ok = st.form_submit_button("Add")
    if add_ok and name.strip():
        with engine.begin() as conn:
            conn.execute(contacts.insert().values(
                name=name, email=email, company=company, phone=phone,
                stage=stage, owner_id=user["id"], created_at=datetime.utcnow()
            ))
        st.success("Contact added.")

    # List + inline edit
    @st.cache_data(ttl=5)
    def load_my_contacts(uid: int):
        with engine.begin() as conn:
            return pd.read_sql(text("""
                SELECT id, name, email, company, phone, stage, created_at
                FROM contacts WHERE owner_id=:uid ORDER BY id DESC
            """), conn, params={"uid": uid})

    df = load_my_contacts(user["id"])
    edited = st.data_editor(
        df, num_rows="dynamic", use_container_width=True,
        column_config={"id": st.column_config.NumberColumn("ID", disabled=True)}
    )
    if not edited.equals(df):
        with engine.begin() as conn:
            # Upserts/updates
            for _, row in edited.iterrows():
                if pd.isna(row["id"]):
                    conn.execute(contacts.insert().values(
                        name=row["name"] or "",
                        email=row.get("email",""),
                        company=row.get("company",""),
                        phone=row.get("phone",""),
                        stage=row.get("stage","Lead"),
                        owner_id=user["id"], created_at=datetime.utcnow(),
                    ))
                else:
                    conn.execute(text("""
                        UPDATE contacts SET name=:name,email=:email,company=:company,
                            phone=:phone,stage=:stage
                        WHERE id=:id AND owner_id=:owner
                    """), {
                        "name": row["name"] or "",
                        "email": row.get("email",""),
                        "company": row.get("company",""),
                        "phone": row.get("phone",""),
                        "stage": row.get("stage","Lead"),
                        "id": int(row["id"]), "owner": user["id"]
                    })
            # Deletes
            deleted_ids = set(df["id"]) - set(edited["id"].dropna())
            for did in deleted_ids:
                conn.execute(text("DELETE FROM contacts WHERE id=:id AND owner_id=:owner"),
                             {"id": int(did), "owner": user["id"]})
        st.cache_data.clear()
        st.toast("Saved changes.", icon="✅")

# ---------- Router ----------
def main():
    sidebar_user_box()
    u = st.session_state.get("user")

    if not u:
        page_login()
        return

    if u["role"] == "admin":
        menu = st.sidebar.radio("Go to", ["Admin Dashboard", "Agent Dashboard"])
        if menu == "Admin Dashboard":
            page_admin_dashboard()
        else:
            page_agent_dashboard()
    else:
        page_agent_dashboard()

if __name__ == "__main__":
    main()

#################################################################################################