import os
import secrets
from datetime import datetime, timezone
from functools import wraps
from uuid import uuid4

from dotenv import load_dotenv
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from supabase import Client, create_client
from supabase._sync.client import SupabaseException
from werkzeug.security import check_password_hash

if os.getenv("RENDER", "").strip().lower() != "true":
    load_dotenv()


def utc_now():
    return datetime.now(timezone.utc)


class SupabaseService:
    STATUS_LABELS = {
        "pending": "Pending",
        "processing": "Processing",
        "ready": "Ready",
        "rejected": "Rejected",
        "claimed": "Claimed",
    }

    def __init__(self):
        self.url = os.getenv("SUPABASE_URL", "").strip()
        self.key = os.getenv("SUPABASE_KEY", "").strip()
        self.bucket = os.getenv("SUPABASE_BUCKET", "valid-ids").strip()
        self.admin_name = "Admin User"
        self.admin_role = "Administrator"
        self.client: Client | None = None
        self.connection_error = ""
        self.demo_requests = self._seed_demo_requests()

        if self.url and self.key:
            try:
                self.client = create_client(self.url, self.key)
            except SupabaseException as exc:
                self.connection_error = str(exc)
                self.client = None
            except Exception as exc:
                self.connection_error = str(exc)
                self.client = None

    @property
    def enabled(self):
        return self.client is not None

    def _seed_demo_requests(self):
        now = utc_now().strftime("%Y-%m-%d")
        return [
            {
                "id": "demo-1",
                "request_id": "BRG-100001",
                "name": "Juan Dela Cruz",
                "address": "123 Main Street, Barangay Sample",
                "contact": "09123456789",
                "email": "juan@example.com",
                "certificate_type": "Barangay Clearance",
                "purpose": "Employment requirement",
                "status": "pending",
                "status_label": "Pending",
                "date": now,
                "created_at": now,
                "valid_id_url": "",
            },
            {
                "id": "demo-2",
                "request_id": "BRG-100002",
                "name": "Maria Santos",
                "address": "45 Rizal Avenue, Barangay Sample",
                "contact": "09987654321",
                "email": "maria@example.com",
                "certificate_type": "Certificate of Residency",
                "purpose": "School enrollment",
                "status": "processing",
                "status_label": "Processing",
                "date": now,
                "created_at": now,
                "valid_id_url": "",
            },
            {
                "id": "demo-3",
                "request_id": "BRG-100003",
                "name": "Pedro Cruz",
                "address": "Zone 2, Barangay Sample",
                "contact": "09112223333",
                "email": "pedro@example.com",
                "certificate_type": "Business Permit",
                "purpose": "Business renewal",
                "status": "ready",
                "status_label": "Ready",
                "date": now,
                "created_at": now,
                "valid_id_url": "",
            },
        ]

    def _format_status_label(self, value):
        return self.STATUS_LABELS.get(value, value.title())

    def _format_request(self, row):
        created_at = row.get("created_at") or utc_now().isoformat()
        date_label = created_at[:10]
        status = (row.get("status") or "pending").lower()
        file_path = row.get("valid_id_url") or ""
        return {
            "id": row.get("id"),
            "request_id": row.get("request_id"),
            "name": row.get("full_name"),
            "address": row.get("address"),
            "contact": row.get("contact_number"),
            "email": row.get("email"),
            "certificate_type": row.get("certificate_type"),
            "certificate": row.get("certificate_type"),
            "purpose": row.get("purpose"),
            "status": status,
            "status_label": self._format_status_label(status),
            "date": date_label,
            "created_at": created_at,
            "valid_id_url": file_path,
            "valid_id_path": file_path,
        }

    def _generate_request_id(self):
        return f"BRG-{secrets.token_hex(3).upper()}"

    def ensure_bucket_exists(self):
        if not self.enabled:
            return False

        buckets = self.client.storage.list_buckets()
        for bucket in buckets:
            bucket_id = bucket.get("id") if isinstance(bucket, dict) else getattr(bucket, "id", "")
            if bucket_id == self.bucket:
                return True

        self.client.storage.create_bucket(
            self.bucket,
            options={
                "public": False,
                "allowed_mime_types": ["image/png", "image/jpeg", "image/jpg", "application/pdf"],
                "file_size_limit": 5242880,
            },
        )
        return True

    def verify_admin(self, username, password):
        if self.enabled:
            response = (
                self.client.table("admins")
                .select("id, username, full_name, role, password_hash")
                .eq("username", username)
                .limit(1)
                .execute()
            )
            rows = response.data or []
            if not rows:
                return None

            admin = rows[0]
            password_hash = admin.get("password_hash") or ""
            valid = password_hash == password or (
                password_hash.startswith("pbkdf2:") and check_password_hash(password_hash, password)
            )
            if valid:
                return {
                    "id": admin["id"],
                    "username": admin["username"],
                    "name": admin.get("full_name") or admin["username"],
                    "role": admin.get("role") or self.admin_role,
                }
            return None
        return None

    def create_request(self, payload, uploaded_file):
        request_id = self._generate_request_id()
        now = utc_now().isoformat()
        valid_id_path = ""

        if self.enabled and uploaded_file and uploaded_file.filename:
            self.ensure_bucket_exists()
            extension = os.path.splitext(uploaded_file.filename)[1].lower()
            storage_path = f"{request_id}-{uuid4().hex}{extension}"
            self.client.storage.from_(self.bucket).upload(
                storage_path,
                uploaded_file.read(),
                {"content-type": uploaded_file.mimetype or "application/octet-stream"},
            )
            valid_id_path = storage_path

        row = {
            "request_id": request_id,
            "full_name": payload["full_name"],
            "address": payload["address"],
            "contact_number": payload["contact_number"],
            "email": payload["email"],
            "certificate_type": payload["certificate_type"],
            "purpose": payload["purpose"],
            "status": "pending",
            "valid_id_url": valid_id_path,
            "created_at": now,
        }

        if self.enabled:
            response = self.client.table("certificate_requests").insert(row).execute()
            saved = self._format_request((response.data or [row])[0])
            return saved

        saved = {
            "id": uuid4().hex,
            "request_id": request_id,
            "name": payload["full_name"],
            "address": payload["address"],
            "contact": payload["contact_number"],
            "email": payload["email"],
            "certificate_type": payload["certificate_type"],
            "certificate": payload["certificate_type"],
            "purpose": payload["purpose"],
            "status": "pending",
            "status_label": "Pending",
            "date": now[:10],
            "created_at": now,
            "valid_id_url": valid_id_path,
            "valid_id_path": valid_id_path,
        }
        self.demo_requests.insert(0, saved)
        return saved

    def create_signed_file_url(self, path):
        if not self.enabled or not path:
            return ""

        signed = self.client.storage.from_(self.bucket).create_signed_url(path, 3600)
        if isinstance(signed, dict):
            return signed.get("signedURL") or signed.get("signedUrl") or signed.get("signed_url") or ""
        return getattr(signed, "signedURL", "") or getattr(signed, "signed_url", "")

    def list_requests(self):
        if self.enabled:
            response = (
                self.client.table("certificate_requests")
                .select("*")
                .order("created_at", desc=True)
                .execute()
            )
            return [self._format_request(row) for row in (response.data or [])]

        return self.demo_requests

    def get_request(self, request_id):
        if self.enabled:
            response = (
                self.client.table("certificate_requests")
                .select("*")
                .eq("id", request_id)
                .limit(1)
                .execute()
            )
            rows = response.data or []
            if rows:
                return self._format_request(rows[0])
            return None

        for item in self.demo_requests:
            if item["id"] == request_id:
                return item
        return None

    def update_request_status(self, request_id, status):
        if self.enabled:
            response = (
                self.client.table("certificate_requests")
                .update({"status": status})
                .eq("id", request_id)
                .execute()
            )
            rows = response.data or []
            if rows:
                return self._format_request(rows[0])
            return None

        for item in self.demo_requests:
            if item["id"] == request_id:
                item["status"] = status
                item["status_label"] = self._format_status_label(status)
                return item
        return None

    def track_requests(self, query):
        query = (query or "").strip().lower()
        if not query:
            return []

        requests_data = self.list_requests()
        return [
            item
            for item in requests_data
            if query in item["request_id"].lower() or query in item["email"].lower()
        ]

    def dashboard_payload(self):
        requests_data = self.list_requests()
        counts = {
            "total_requests": len(requests_data),
            "pending": sum(1 for item in requests_data if item["status"] == "pending"),
            "processing": sum(1 for item in requests_data if item["status"] == "processing"),
            "ready": sum(1 for item in requests_data if item["status"] == "ready"),
        }
        return {
            "admin": {
                "name": session.get("admin_name", self.admin_name),
                "role": session.get("admin_role", self.admin_role),
            },
            "stats": counts,
            "status_choices": [
                {"value": "pending", "label": "Pending"},
                {"value": "processing", "label": "Processing"},
                {"value": "ready", "label": "Ready"},
                {"value": "rejected", "label": "Rejected"},
                {"value": "claimed", "label": "Claimed"},
            ],
            "requests": requests_data,
        }

    def reports_payload(self):
        requests_data = self.list_requests()
        total = len(requests_data)

        certificate_counts = {}
        status_counts = {"pending": 0, "processing": 0, "ready": 0, "claimed": 0}

        for item in requests_data:
            certificate_counts[item["certificate_type"]] = certificate_counts.get(item["certificate_type"], 0) + 1
            if item["status"] in status_counts:
                status_counts[item["status"]] += 1

        certificate_rows = []
        for name, count in sorted(certificate_counts.items(), key=lambda item: item[1], reverse=True):
            percent = round((count / total) * 100) if total else 0
            certificate_rows.append({"name": name, "label": f"{count} requests", "percent": percent})

        avg_processing_days = 1 if total else 0
        satisfaction = 98 if total else 0

        return {
            "admin": {
                "name": session.get("admin_name", self.admin_name),
                "role": session.get("admin_role", self.admin_role),
            },
            "stats": [
                {"title": "This Month", "value": str(total), "helper": f"{total} requests received", "icon": "requests"},
                {"title": "Avg. Processing Time", "value": str(avg_processing_days), "helper": "days", "icon": "processing"},
                {"title": "Satisfaction Rate", "value": f"{satisfaction}%", "helper": "estimated", "icon": "satisfaction"},
                {"title": "Active Residents", "value": str(len({item['email'] for item in requests_data})), "helper": "requesting users", "icon": "residents"},
            ],
            "certificates": certificate_rows,
            "statuses": [
                {"label": "Pending", "value": status_counts["pending"], "color": "pending"},
                {"label": "Processing", "value": status_counts["processing"], "color": "processing"},
                {"label": "Ready to Claim", "value": status_counts["ready"], "color": "ready"},
                {"label": "Claimed", "value": status_counts["claimed"], "color": "claimed"},
            ],
            "reportTypes": [
                {"value": "requests-summary", "label": "Requests Summary"},
                {"value": "certificate-demand", "label": "Certificate Demand"},
                {"value": "status-breakdown", "label": "Status Breakdown"},
            ],
            "dateRanges": [
                {"value": "7d", "label": "Last 7 days"},
                {"value": "30d", "label": "Last 30 days"},
                {"value": "year", "label": "This year"},
            ],
            "formats": [
                {"value": "pdf", "label": "PDF"},
                {"value": "csv", "label": "CSV"},
            ],
        }


app = Flask(__name__)

secret_key = os.getenv("FLASK_SECRET_KEY", "").strip()
is_render = os.getenv("RENDER", "").strip().lower() == "true"

if not secret_key:
    if is_render:
        raise RuntimeError("FLASK_SECRET_KEY must be set in Render environment variables.")
    secret_key = "dev-only-secret-key"

app.secret_key = secret_key
service = SupabaseService()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def validate_request_form(form):
    required_fields = {
        "full_name": "Full name is required.",
        "address": "Address is required.",
        "contact_number": "Contact number is required.",
        "email": "Email is required.",
        "certificate_type": "Certificate type is required.",
        "purpose": "Purpose is required.",
    }
    payload = {}
    for field, message in required_fields.items():
        value = (form.get(field) or "").strip()
        if not value or value.lower().startswith("select a certificate"):
            raise ValueError(message)
        payload[field] = value
    return payload


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/request")
def request_page():
    return render_template("brgy_request.html")


@app.route("/track")
def track_page():
    return render_template("brgy_track.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        admin = service.verify_admin(username, password)
        if not admin:
            flash("Invalid username or password.", "danger")
            return render_template("brgy_login.html")

        session["admin_id"] = admin["id"]
        session["admin_name"] = admin["name"]
        session["admin_role"] = admin["role"]
        return redirect(url_for("admin_dashboard"))

    return render_template("brgy_login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin/dashboard")
@login_required
def admin_dashboard():
    return render_template("admin_dashboard.html")


@app.route("/admin/requests/<request_id>")
@login_required
def request_details(request_id):
    return render_template("request_details.html", request_id=request_id)


@app.route("/admin/reports")
@login_required
def admin_reports():
    return render_template("admin_reports_analytics.html")


@app.route("/api/requests", methods=["POST"])
def api_create_request():
    try:
        payload = validate_request_form(request.form)
        saved = service.create_request(payload, request.files.get("valid_id"))
        return jsonify(
            {
                "message": "Request submitted successfully.",
                "request_id": saved["request_id"],
                "request": saved,
            }
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": f"Unable to submit request: {exc}"}), 500


@app.route("/api/track")
def api_track():
    query = request.args.get("query", "")
    return jsonify({"results": service.track_requests(query)})


@app.route("/api/admin/dashboard/")
@login_required
def api_admin_dashboard():
    return jsonify(service.dashboard_payload())


@app.route("/api/admin/reports/")
@login_required
def api_admin_reports():
    return jsonify(service.reports_payload())


@app.route("/api/request/<request_id>", methods=["GET", "PATCH"])
@login_required
def api_request(request_id):
    if request.method == "GET":
        item = service.get_request(request_id)
        if not item:
            abort(404)
        return jsonify(
            {
                "admin": {
                    "name": session.get("admin_name", service.admin_name),
                    "role": session.get("admin_role", service.admin_role),
                },
                "signed_valid_id_url": service.create_signed_file_url(item.get("valid_id_path") or item.get("valid_id_url")),
                **item,
            }
        )

    data = request.get_json(silent=True) or {}
    status = (data.get("status") or "").strip().lower()
    if status not in {"pending", "processing", "ready", "rejected", "claimed"}:
        return jsonify({"error": "Invalid status."}), 400

    item = service.update_request_status(request_id, status)
    if not item:
        abort(404)
    return jsonify(item)


@app.route("/health")
def health():
    return jsonify({"ok": True, "supabase_enabled": service.enabled, "connection_error": service.connection_error})


if __name__ == "__main__":
    app.run(debug=True)
