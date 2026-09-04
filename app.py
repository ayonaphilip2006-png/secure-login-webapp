from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from passlib.context import CryptContext

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

users = {}


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html>
    <head>
        <title>Secure Login</title>
    </head>
    <body>
        <h1>Secure Login Web App</h1>

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

    hashed_password = pwd_context.hash(password)
    users[username] = hashed_password

    return """
    <h2>Registration successful!</h2>
    <p>Your password has been securely hashed.</p>
    <a href="/">Go to Login</a>
    """


@app.post("/login", response_class=HTMLResponse)
def login(username: str = Form(...), password: str = Form(...)):
    if username not in users:
        return "<h2>Invalid username or password</h2><a href='/'>Go Back</a>"

    if pwd_context.verify(password, users[username]):
        return "<h2>Login successful!</h2>"

    return "<h2>Invalid username or password</h2><a href='/'>Go Back</a>"
