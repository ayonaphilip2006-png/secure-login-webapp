from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
import bcrypt
import os

app = FastAPI(title="Secure Login Web App")

# Secret key for sessions
SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret-in-production")

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=False,
    same_site="lax"
)

# Database
DATABASE_URL = "sqlite:///./users.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)


Base.metadata.create_all(bind=engine)


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Login</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f2f4f7;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
            }

            .box {
                background: white;
                padding: 30px;
                border-radius: 12px;
                width: 90%;
                max-width: 400px;
                box-shadow: 0 5px 20px rgba(0,0,0,.15);
                text-align: center;
            }

            input {
                width: 90%;
                padding: 12px;
                margin: 8px;
                border: 1px solid #ccc;
                border-radius: 6px;
            }

            button {
                width: 95%;
                padding: 12px;
                margin-top: 10px;
                border: none;
                border-radius: 6px;
                background: #2563eb;
                color: white;
                font-size: 16px;
            }

            a {
                display: block;
                margin-top: 15px;
                color: #2563eb;
            }
        </style>
    </head>

    <body>
        <div class="box">
            <h1>🔐 Secure Login</h1>
            <p>Login to your account</p>

            <form method="post" action="/login">
                <input type="email" name="email"
                       placeholder="Email" required>

                <input type="password" name="password"
                       placeholder="Password" required>

                <button type="submit">Login</button>
            </form>

            <a href="/register">Create an account</a>
        </div>
    </body>
    </html>
    """


@app.get("/register", response_class=HTMLResponse)
def register_page():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f2f4f7;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
            }

            .box {
                background: white;
                padding: 30px;
                border-radius: 12px;
                width: 90%;
                max-width: 400px;
                box-shadow: 0 5px 20px rgba(0,0,0,.15);
                text-align: center;
            }

            input {
                width: 90%;
                padding: 12px;
                margin: 8px;
                border: 1px solid #ccc;
                border-radius: 6px;
            }

            button {
                width: 95%;
                padding: 12px;
                background: #16a34a;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 16px;
            }

            a {
                display: block;
                margin-top: 15px;
            }
        </style>
    </head>

    <body>
        <div class="box">
            <h1>🛡️ Register</h1>

            <form method="post" action="/register">
                <input type="text" name="name"
                       placeholder="Full Name"
                       maxlength="100" required>

                <input type="email" name="email"
                       placeholder="Email"
                       maxlength="150" required>

                <input type="password" name="password"
                       placeholder="Password"
                       minlength="8" required>

                <button type="submit">Create Account</button>
            </form>

            <a href="/">Already have an account? Login</a>
        </div>
    </body>
    </html>
    """


@app.post("/register")
def register(
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    name = name.strip()
    email = email.strip().lower()

    # Basic server-side validation
    if len(name) < 2:
        return HTMLResponse("Invalid name.", status_code=400)

    if len(password) < 8:
        return HTMLResponse(
            "Password must contain at least 8 characters.",
            status_code=400
        )

    db = SessionLocal()

    try:
        existing_user = db.query(User).filter(
            User.email == email
        ).first()

        if existing_user:
            return HTMLResponse(
                "Unable to create account. Please use another email.",
                status_code=400
            )

        # Secure password hashing using bcrypt
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        ).decode("utf-8")

        user = User(
            name=name,
            email=email,
            password_hash=password_hash
        )

        db.add(user)
        db.commit()

        return RedirectResponse(
            url="/",
            status_code=303
        )

    finally:
        db.close()


@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...)
):
    email = email.strip().lower()

    db = SessionLocal()

    try:
        user = db.query(User).filter(
            User.email == email
        ).first()

        # Generic error prevents account enumeration
        if not user:
            return HTMLResponse(
                "Invalid email or password.",
                status_code=401
            )

        if not bcrypt.checkpw(
            password.encode("utf-8"),
            user.password_hash.encode("utf-8")
        ):
            return HTMLResponse(
                "Invalid email or password.",
                status_code=401
            )

        # Store only user ID in session
        request.session["user_id"] = user.id

        return RedirectResponse(
            url="/dashboard",
            status_code=303
        )

    finally:
        db.close()


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user_id = request.session.get("user_id")

    if not user_id:
        return RedirectResponse(
            url="/",
            status_code=303
        )

    db = SessionLocal()

    try:
        user = db.query(User).filter(
            User.id == user_id
        ).first()

        if not user:
            request.session.clear()
            return RedirectResponse(
                url="/",
                status_code=303
            )

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: Arial;
                    background: #f2f4f7;
                    text-align: center;
                    padding-top: 100px;
                }}

                .box {{
                    background: white;
                    padding: 30px;
                    margin: auto;
                    width: 85%;
                    max-width: 500px;
                    border-radius: 12px;
                    box-shadow: 0 5px 20px rgba(0,0,0,.15);
                }}

                button {{
                    padding: 12px 25px;
                    background: #dc2626;
                    color: white;
                    border: none;
                    border-radius: 6px;
                }}
            </style>
        </head>

        <body>
            <div class="box">
                <h1>Welcome, {user.name}!</h1>
                <p>You are successfully logged in.</p>
                <p>🔒 Your session is active.</p>

                <form method="post" action="/logout">
                    <button type="submit">Logout</button>
                </form>
            </div>
        </body>
        </html>
        """

    finally:
        db.close()


@app.post("/logout")
def logout(request: Request):
    request.session.clear()

    return RedirectResponse(
        url="/",
        status_code=303
    )
