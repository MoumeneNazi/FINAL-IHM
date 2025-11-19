from fastapi import FastAPI, HTTPException, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from database import SessionLocal, engine
from models import Base, User, RevokedToken
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import secrets

security = HTTPBearer()

load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY") or os.environ.get("SECRET_KEY") or secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

Base.metadata.create_all(bind=engine)

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = secrets.token_urlsafe(16)
    to_encode.update({"exp": expire, "jti": jti})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user_from_token(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        jti: str = payload.get("jti")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    # check for revoked token
    if jti:
        revoked = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
        if revoked:
            raise HTTPException(status_code=401, detail="Token has been revoked")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    admin = db.query(User).filter(User.username == "admin").first()
    if not admin:
        hashed_pw = hash_password("admin123")
        admin_user = User(full_name="Admin", username="admin", password=hashed_pw, email="admin@example.com", role="admin")
        db.add(admin_user)
        db.commit()
    db.close()


@app.get("/", response_class=HTMLResponse)
def read_root():
    try:
        with open("static/login.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Login page not found</h1>"


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": username, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/register", response_class=HTMLResponse)
def register_page():
    try:
        with open("static/register.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Register page not found</h1>"


@app.post("/register")
def register(full_name: str = Form(...), username: str = Form(...), password: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    hashed_pw = hash_password(password)
    new_user = User(full_name=full_name, username=username, password=hashed_pw, email=email, role="user")
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}


@app.get("/user", response_class=HTMLResponse)
def user_page():
    try:
        with open("static/user.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="User page not found")


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    try:
        with open("static/admin.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Admin page not found")


@app.post("/change_password")
def change_password(old_password: str = Form(...), new_password: str = Form(...), current_user: User = Depends(get_current_user_from_token), db: Session = Depends(get_db)):
    if not verify_password(old_password, current_user.password):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    current_user.password = hash_password(new_password)
    db.commit()
    return {"message": "Password changed successfully"}


@app.get("/admin/users")
def view_users(current_user: User = Depends(get_current_user_from_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    users = db.query(User).all()
    return [{"username": u.username, "full_name": u.full_name, "email": u.email, "role": u.role} for u in users]


@app.post("/admin/users/{username}/set_password")
def admin_set_user_password(username: str, new_password: str = Form(...), current_user: User = Depends(get_current_user_from_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.password = hash_password(new_password)
    db.commit()
    return {"message": "User password updated"}


@app.post("/admin/users/{username}/set_role")
def admin_set_user_role(username: str, role: str = Form(...), current_user: User = Depends(get_current_user_from_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    if role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Invalid role")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = role
    db.commit()
    return {"message": "User role updated"}


@app.get("/me")
def get_me(current_user: User = Depends(get_current_user_from_token)):
    return {"username": current_user.username, "full_name": current_user.full_name, "role": current_user.role}


@app.post("/logout")
def logout(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti: str = payload.get("jti")
        if not jti:
            raise HTTPException(status_code=400, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    existing = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
    if not existing:
        revoked = RevokedToken(jti=jti)
        db.add(revoked)
        db.commit()
    return {"message": "Logged out"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

