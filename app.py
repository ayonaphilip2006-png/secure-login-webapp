from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key="change-this-secret-key"
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

users = {}


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
    <head>
        <title>Secure Login System</title>
    </head>
    <body>
        <h1>Secure Login System</h1>

        <h2>Register</h2>
        <form action="/register" method="post">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Register</button>
        </form>

        <h2>Login</h2>
        <form action="/login" method="post">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """


@app.post("/register", response_class=HTMLResponse)
def register(username: str = Form(...), password: str = Form(...)):

    if username in users:
        return "<h2>User already exists!</h2><a href='/'>Go Back</a>"

    if len(username) < 3 or len(password) < 6:
        return "<h2>Invalid input!</h2><p>Username must be 3+ characters and password 6+ characters.</p><a href='/'>Go Back</a>"

    hashed_password = pwd_context.hash(password)
    users[username] = hashed_password

    return "<h2>Registration successful!</h2><a href='/'>Go to Login</a>"


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):

    if username not in users:
        return "<h2>Invalid username or password</h2><a href='/'>Go Back</a>"

    if pwd_context.verify(password, users[username]):

        request.session["username"] = username

        return """
        <h2>Login successful!</h2>
        <p>You are now logged in.</p>
        <a href="/dashboard">Go to Dashboard</a>
        """

    return "<h2>Invalid username or password</h2><a href='/'>Go Back</a>"


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):

    username = request.session.get("username")

    if not username:
        return RedirectResponse("/", status_code=303)

    return f"""
    <h1>Welcome, {username}!</h1>
    <p>You are logged in securely.</p>
    <a href="/logout">Logout</a>
    """


@app.get("/logout")
def logout(request: Request):

    request.session.clear()

    return RedirectResponse("/", status_code=303)
