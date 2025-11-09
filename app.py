from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Optional, List

from dotenv import load_dotenv
from fastapi import FastAPI, Query, HTTPException, Depends, Path, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import (
    create_engine,
    select,
    func,
    and_,
    text,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.types import Text as SA_Text, DateTime as SA_DateTime, Integer as SA_Integer, Boolean as SA_Boolean

import jwt

# ---------------------- Инициализация ----------------------
load_dotenv()

RAW_DB_URL = os.getenv("DATABASE_URL")
if not RAW_DB_URL:
    raise RuntimeError("DATABASE_URL не задан в .env")

if RAW_DB_URL.startswith("postgresql://"):
    SQLA_DB_URL = RAW_DB_URL.replace("postgresql://", "postgresql+psycopg2://", 1)
else:
    SQLA_DB_URL = RAW_DB_URL

engine = create_engine(
    SQLA_DB_URL,
    pool_pre_ping=True,
    future=True
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

app = FastAPI(title="TrackingApp API", version="1.2")

# ---------------------- Авторизация ----------------------
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"

# Значения уровней доступа используются в существующих фильтрах на фронтенде
ROLE_LEVELS = {
    "operator": 0,
    "admin": 1,
    "viewer": 2,
}

# Базовые пароли уровня доступа сохраняются для обратной совместимости и админ-входа
PASSWORDS = {
    "301993": ROLE_LEVELS["admin"],
    "123123123": ROLE_LEVELS["operator"],
    "321321321": ROLE_LEVELS["viewer"],
}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

security = HTTPBearer()


def hash_password(raw_password: str) -> str:
    return pwd_context.hash(raw_password)


def verify_password(raw_password: str, password_hash: str) -> bool:
    return pwd_context.verify(raw_password, password_hash)


def create_token(level: int, *, user_id: Optional[int] = None, surname: Optional[str] = None) -> str:
    payload = {
        "level": level,
        "exp": datetime.now() + timedelta(hours=12),
    }
    if user_id is not None:
        payload["user_id"] = user_id
    if surname is not None:
        payload["surname"] = surname
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        level = payload.get("level")
        if level is None:
            raise HTTPException(status_code=401, detail="Невірний токен")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Термін дії токена минув")
    except Exception:
        raise HTTPException(status_code=401, detail="Невірний або протермінований токен")


def require_admin(payload: dict = Depends(verify_token)) -> dict:
    if int(payload.get("level", -1)) != ROLE_LEVELS["admin"]:
        raise HTTPException(status_code=403, detail="Доступ тільки для адміністратора")
    return payload


def require_write(payload: dict = Depends(verify_token)) -> dict:
    if int(payload.get("level", -1)) not in (ROLE_LEVELS["operator"], ROLE_LEVELS["admin"]):
        raise HTTPException(status_code=403, detail="Недостатньо прав для цієї дії")
    return payload


def require_admin_or_error_access(payload: dict = Depends(verify_token)) -> dict:
    if int(payload.get("level", -1)) not in (ROLE_LEVELS["operator"], ROLE_LEVELS["admin"]):
        raise HTTPException(status_code=403, detail="Недостатньо прав для цієї дії")
    return payload


def require_read(payload: dict = Depends(verify_token)) -> dict:
    return payload


# ---------------------- Модели БД ----------------------
class Base(DeclarativeBase):
    pass


class Tracking(Base):
    __tablename__ = "tracking"
    id: Mapped[int] = mapped_column(SA_Integer, primary_key=True, autoincrement=True)
    user_name: Mapped[str] = mapped_column(SA_Text, nullable=False)
    boxid: Mapped[str] = mapped_column(SA_Text, nullable=False)
    ttn: Mapped[str] = mapped_column(SA_Text, nullable=False)
    datetime: Mapped[datetime] = mapped_column(SA_DateTime, nullable=False)
    note: Mapped[Optional[str]] = mapped_column(SA_Text, nullable=True)


class ErrorLog(Base):
    __tablename__ = "errors"
    id: Mapped[int] = mapped_column(SA_Integer, primary_key=True, autoincrement=True)
    user_name: Mapped[str] = mapped_column(SA_Text, nullable=False)
    boxid: Mapped[str] = mapped_column(SA_Text, nullable=False)
    ttn: Mapped[str] = mapped_column(SA_Text, nullable=False)
    datetime: Mapped[datetime] = mapped_column(SA_DateTime, nullable=False)
    error_message: Mapped[str] = mapped_column(SA_Text, nullable=False)


class Settings(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(SA_Integer, primary_key=True, autoincrement=True)
    auto_export: Mapped[bool] = mapped_column(SA_Boolean, nullable=False, default=False)
    auto_save: Mapped[bool] = mapped_column(SA_Boolean, nullable=False, default=True)
    export_directory: Mapped[str] = mapped_column(SA_Text, nullable=False, default="")


class HelpInfo(Base):
    __tablename__ = "help_info"
    id: Mapped[int] = mapped_column(SA_Integer, primary_key=True)
    text_content: Mapped[str] = mapped_column(SA_Text, nullable=False)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("surname", name="uq_users_surname"),)

    id: Mapped[int] = mapped_column(SA_Integer, primary_key=True, autoincrement=True)
    surname: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(SA_Text, nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="operator")
    is_active: Mapped[bool] = mapped_column(SA_Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(SA_DateTime, nullable=False, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(SA_DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class RegistrationRequest(Base):
    __tablename__ = "registration_requests"
    __table_args__ = (UniqueConstraint("surname", name="uq_registration_requests_surname"),)

    id: Mapped[int] = mapped_column(SA_Integer, primary_key=True, autoincrement=True)
    surname: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(SA_Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(SA_DateTime, nullable=False, default=datetime.utcnow)


with engine.begin() as conn:
    Base.metadata.create_all(conn)
    conn.execute(text(
        """
        INSERT INTO help_info (id, text_content)
        VALUES (1, 'Поки що інструкція відсутня. Натисніть «Добавить/Изменить инструкцію», щоб додати.')
        ON CONFLICT (id) DO NOTHING
        """
    ))
    conn.execute(text(
        """
        INSERT INTO settings (id, auto_export, auto_save, export_directory)
        VALUES (1, FALSE, TRUE, '')
        ON CONFLICT (id) DO NOTHING
        """
    ))


# ---------------------- Pydantic-схемы ----------------------
class AddRecordIn(BaseModel):
    user_name: str = Field(..., min_length=1)
    boxid: str = Field(..., min_length=1)
    ttn: str = Field(..., min_length=1)


class AddRecordOut(BaseModel):
    status: str
    note: str


class HistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    user_name: str
    boxid: str
    ttn: str
    datetime: datetime
    note: Optional[str] = None


class ErrorItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    user_name: str
    boxid: str
    ttn: str
    datetime: datetime
    error_message: str


class HelpGetOut(BaseModel):
    text_content: str


class HelpSetIn(BaseModel):
    text_content: str


class AddErrorIn(BaseModel):
    user_name: str
    boxid: str
    ttn: str
    message: str


class LoginRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Пароль доступа или пароль пользователя")
    surname: Optional[str] = Field(None, description="Фамилия пользователя для входа по личному паролю")


class LoginResponse(BaseModel):
    token: str
    access_level: int
    role: str
    surname: Optional[str] = None


class RegistrationIn(BaseModel):
    surname: str = Field(..., min_length=1)
    password: str = Field(..., min_length=6)


class RegistrationRequestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    surname: str
    created_at: datetime


class ApproveRegistrationIn(BaseModel):
    role: str = Field(..., pattern="^(admin|operator|viewer)$")


class UpdateUserIn(BaseModel):
    role: Optional[str] = Field(None, pattern="^(admin|operator|viewer)$")
    is_active: Optional[bool] = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    surname: str
    role: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


# ---------------------- Вспомогательные функции ----------------------
def get_session():
    return SessionLocal()


def check_duplicates(db, boxid: str, ttn: str):
    """Возвращает (note, exists_exact, exists_box, exists_ttn)."""
    exists_exact = db.execute(
        select(Tracking.id).where(and_(Tracking.boxid == boxid, Tracking.ttn == ttn))
    ).first() is not None

    exists_box = db.execute(
        select(Tracking.id).where(Tracking.boxid == boxid)
    ).first() is not None

    exists_ttn = db.execute(
        select(Tracking.id).where(Tracking.ttn == ttn)
    ).first() is not None

    if exists_exact:
        note = "Комбінація цього BoxID та цього ТТН вже є в базі"
    elif exists_box:
        note = "Такий BoxID вже був у базі"
    elif exists_ttn:
        note = "Такий номер ТТН вже був у базі"
    else:
        note = ""

    return note, exists_exact, exists_box, exists_ttn


def ensure_role(role: str) -> str:
    if role not in ROLE_LEVELS:
        raise HTTPException(status_code=400, detail="Невідомий рівень доступу")
    return role


# ---------------------- Эндпоинты ----------------------
@app.get("/")
def root():
    return {"status": "online", "message": "TrackingApp API працює"}


@app.post("/login", response_model=LoginResponse)
def login(
    payload: Optional[LoginRequest] = Body(
        default=None,
        description="Данные для входа. Если не переданы, используются query-параметры",
    ),
    password: Optional[str] = Query(
        default=None,
        description="Пароль доступа или пароль пользователя (для обратной сумісності)",
    ),
    surname: Optional[str] = Query(
        default=None,
        description="Фамилия пользователя при входе по особистому паролю",
    ),
):
    if payload is not None:
        # Приоритет у тела запроса, щоб працювало з оновленим фронтендом
        password = payload.password
        surname = payload.surname

    if not password:
        raise HTTPException(status_code=400, detail="Пароль обов'язковий")

    # Вход по персональным данным
    if surname:
        db = get_session()
        try:
            stmt = select(User).where(User.surname.ilike(surname))
            user = db.execute(stmt).scalar_one_or_none()
            if not user or not user.is_active:
                raise HTTPException(status_code=401, detail="Користувач не активний або не існує")
            if not verify_password(password, user.password_hash):
                raise HTTPException(status_code=401, detail="Невірний пароль")
            role = ensure_role(user.role)
            level = ROLE_LEVELS[role]
            token = create_token(level, user_id=user.id, surname=user.surname)
            return LoginResponse(token=token, access_level=level, role=role, surname=user.surname)
        finally:
            db.close()

    # Вход по прежним паролям (администратор и вспомогательные доступы)
    if password not in PASSWORDS:
        raise HTTPException(status_code=401, detail="Невірний пароль")
    level = PASSWORDS[password]
    role = next((name for name, lvl in ROLE_LEVELS.items() if lvl == level), "operator")
    token = create_token(level)
    return LoginResponse(token=token, access_level=level, role=role)


@app.post("/admin_login", response_model=LoginResponse)
def admin_login(
    payload: Optional[LoginRequest] = Body(
        default=None,
        description="Пароль адміністратора. Якщо не переданий, використовується query-параметр",
    ),
    password: Optional[str] = Query(
        default=None,
        description="Пароль адміністратора для швидкого входу",
    ),
):
    if payload is not None:
        password = payload.password

    if not password:
        raise HTTPException(status_code=400, detail="Пароль адміністратора обов'язковий")

    level = PASSWORDS.get(password)
    if level != ROLE_LEVELS["admin"]:
        raise HTTPException(status_code=401, detail="Невірний пароль адміністратора")

    token = create_token(level)
    return LoginResponse(token=token, access_level=level, role="admin")


@app.post("/register", response_model=RegistrationRequestOut)
def register(payload: RegistrationIn):
    db = get_session()
    try:
        normalized_surname = payload.surname.strip()
        if not normalized_surname:
            raise HTTPException(status_code=400, detail="Фамилия не може бути порожньою")

        existing_user = db.execute(select(User.id).where(User.surname.ilike(normalized_surname))).first()
        if existing_user:
            raise HTTPException(status_code=409, detail="Користувач з такою фамілією вже існує")

        existing_request = db.execute(
            select(RegistrationRequest.id).where(RegistrationRequest.surname.ilike(normalized_surname))
        ).first()
        if existing_request:
            raise HTTPException(status_code=409, detail="Заявка з такою фамілією вже існує")

        req = RegistrationRequest(
            surname=normalized_surname,
            password_hash=hash_password(payload.password),
        )
        db.add(req)
        db.commit()
        db.refresh(req)
        return req
    finally:
        db.close()


@app.get("/admin/registration_requests", response_model=List[RegistrationRequestOut])
def list_registration_requests(_: dict = Depends(require_admin)):
    db = get_session()
    try:
        stmt = select(RegistrationRequest).order_by(RegistrationRequest.created_at.asc())
        return db.execute(stmt).scalars().all()
    finally:
        db.close()


@app.post("/admin/registration_requests/{request_id}/approve", response_model=UserOut)
def approve_registration(
    payload: ApproveRegistrationIn,
    request_id: int = Path(..., gt=0),
    _: dict = Depends(require_admin),
):
    role = ensure_role(payload.role)
    db = get_session()
    try:
        req = db.get(RegistrationRequest, request_id)
        if not req:
            raise HTTPException(status_code=404, detail="Заявку не знайдено")

        user = User(
            surname=req.surname,
            password_hash=req.password_hash,
            role=role,
            is_active=True,
        )
        db.add(user)
        db.delete(req)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


@app.post("/admin/registration_requests/{request_id}/reject")
def reject_registration(request_id: int = Path(..., gt=0), _: dict = Depends(require_admin)):
    db = get_session()
    try:
        req = db.get(RegistrationRequest, request_id)
        if not req:
            raise HTTPException(status_code=404, detail="Заявку не знайдено")
        db.delete(req)
        db.commit()
        return {"status": "rejected", "id": request_id}
    finally:
        db.close()


@app.get("/admin/users", response_model=List[UserOut])
def list_users(_: dict = Depends(require_admin)):
    db = get_session()
    try:
        stmt = select(User).order_by(User.created_at.asc())
        return db.execute(stmt).scalars().all()
    finally:
        db.close()


@app.patch("/admin/users/{user_id}", response_model=UserOut)
def update_user(
    payload: UpdateUserIn,
    user_id: int = Path(..., gt=0),
    _: dict = Depends(require_admin),
):
    if payload.role is None and payload.is_active is None:
        raise HTTPException(status_code=400, detail="Нічого оновлювати")

    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Користувача не знайдено")

        if payload.role is not None:
            user.role = ensure_role(payload.role)
        if payload.is_active is not None:
            user.is_active = payload.is_active

        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


@app.post("/admin/users/{user_id}/reset_password")
def reset_user_password(
    new_password: str = Query(..., min_length=6),
    user_id: int = Path(..., gt=0),
    _: dict = Depends(require_admin),
):
    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Користувача не знайдено")
        user.password_hash = hash_password(new_password)
        db.commit()
        return {"status": "password_reset", "id": user_id}
    finally:
        db.close()


@app.post("/admin/users/{user_id}/deactivate")
def deactivate_user(user_id: int = Path(..., gt=0), _: dict = Depends(require_admin)):
    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Користувача не знайдено")
        user.is_active = False
        db.commit()
        return {"status": "deactivated", "id": user_id}
    finally:
        db.close()


@app.post("/admin/users/{user_id}/activate")
def activate_user(user_id: int = Path(..., gt=0), _: dict = Depends(require_admin)):
    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Користувача не знайдено")
        user.is_active = True
        db.commit()
        return {"status": "activated", "id": user_id}
    finally:
        db.close()


@app.post("/admin/users")
def create_user(
    payload: ApproveRegistrationIn,
    surname: str = Query(..., min_length=1),
    password: str = Query(..., min_length=6),
    _: dict = Depends(require_admin),
):
    role = ensure_role(payload.role)
    db = get_session()
    try:
        normalized_surname = surname.strip()
        if not normalized_surname:
            raise HTTPException(status_code=400, detail="Фамилия не може бути порожньою")

        existing_user = db.execute(select(User.id).where(User.surname.ilike(normalized_surname))).first()
        if existing_user:
            raise HTTPException(status_code=409, detail="Користувач з такою фамілією вже існує")

        user = User(
            surname=normalized_surname,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


@app.post("/admin/users/{user_id}/change_role")
def change_user_role(
    payload: ApproveRegistrationIn,
    user_id: int = Path(..., gt=0),
    _: dict = Depends(require_admin),
):
    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Користувача не знайдено")
        user.role = ensure_role(payload.role)
        db.commit()
        return {"status": "role_updated", "id": user_id, "role": user.role}
    finally:
        db.close()


@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int = Path(..., gt=0), _: dict = Depends(require_admin)):
    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Користувача не знайдено")
        db.delete(user)
        db.commit()
        return {"status": "deleted", "id": user_id}
    finally:
        db.close()


@app.post("/admin/users/{user_id}/set_password")
def set_user_password(
    new_password: str = Query(..., min_length=6),
    user_id: int = Path(..., gt=0),
    _: dict = Depends(require_admin),
):
    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Користувача не знайдено")
        user.password_hash = hash_password(new_password)
        db.commit()
        return {"status": "password_updated", "id": user_id}
    finally:
        db.close()


@app.post("/admin/users/{user_id}/set_activity")
def set_user_activity(
    is_active: bool = Query(...),
    user_id: int = Path(..., gt=0),
    _: dict = Depends(require_admin),
):
    db = get_session()
    try:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Користувача не знайдено")
        user.is_active = is_active
        db.commit()
        return {"status": "activity_updated", "id": user_id, "is_active": is_active}
    finally:
        db.close()


@app.get("/admin/role-passwords")
def get_role_passwords(_: dict = Depends(require_admin)):
    return PASSWORDS


@app.post("/admin/role-passwords/{role}")
def set_role_password(
    role: str,
    password: str = Query(..., min_length=3),
    _: dict = Depends(require_admin),
):
    role = ensure_role(role)
    PASSWORDS[password] = ROLE_LEVELS[role]
    return {"status": "updated", "role": role}


@app.post("/add_record", response_model=AddRecordOut)
def add_record(payload: AddRecordIn, _: dict = Depends(require_write)):
    db = get_session()
    try:
        note, exists_exact, exists_box, exists_ttn = check_duplicates(db, payload.boxid, payload.ttn)

        # Всегда пишем в историю
        rec = Tracking(
            user_name=payload.user_name,
            boxid=payload.boxid,
            ttn=payload.ttn,
            datetime=datetime.now(),
            note=note
        )
        db.add(rec)

        # Если это не точный дубликат, но есть совпадение по boxid или ttn — создаем запись ошибки
        if not exists_exact and (exists_box or exists_ttn):
            if exists_box and exists_ttn:
                err_msg = "BoxID та ТТН вже використовуються в інших поєднаннях"
            elif exists_box:
                err_msg = "BoxID вже використовується в іншому поєднанні"
            else:
                err_msg = "ТТН вже використовується в іншому поєднанні"

            err = ErrorLog(
                user_name=payload.user_name,
                boxid=payload.boxid,
                ttn=payload.ttn,
                datetime=datetime.now(),
                error_message=err_msg
            )
            db.add(err)

        db.commit()
        return {"status": "ok", "note": note}
    finally:
        db.close()


@app.get("/get_history", response_model=List[HistoryItem])
def get_history(
    user_name: Optional[str] = Query(default=None),
    boxid: Optional[str] = Query(default=None),
    ttn: Optional[str] = Query(default=None),
    date: Optional[str] = Query(default=None, description="Формат YYYY-MM-DD"),
    duplicates_only: bool = Query(default=False),
    _: dict = Depends(require_read)
):
    db = get_session()
    try:
        stmt = select(Tracking).where(text("1=1"))
        if user_name:
            stmt = stmt.where(Tracking.user_name.ilike(f"{user_name}%"))
        if boxid:
            stmt = stmt.where(Tracking.boxid.ilike(f"{boxid}%"))
        if ttn:
            stmt = stmt.where(Tracking.ttn.ilike(f"{ttn}%"))
        if date:
            try:
                start = datetime.fromisoformat(date + " 00:00:00")
            except ValueError:
                raise HTTPException(status_code=400, detail="date: очікується формат YYYY-MM-DD")
            end = start + timedelta(days=1)
            stmt = stmt.where(and_(Tracking.datetime >= start, Tracking.datetime < end))
        if duplicates_only:
            stmt = stmt.where(func.coalesce(Tracking.note, "") != "")
        stmt = stmt.order_by(Tracking.datetime.desc())
        rows = db.execute(stmt).scalars().all()
        return rows
    finally:
        db.close()


@app.get("/get_errors", response_model=List[ErrorItem])
def get_errors(
    boxid: Optional[str] = Query(default=None),
    ttn: Optional[str] = Query(default=None),
    _: dict = Depends(require_read)
):
    db = get_session()
    try:
        stmt = select(ErrorLog).where(text("1=1"))
        if boxid:
            stmt = stmt.where(ErrorLog.boxid.ilike(f"{boxid}%"))
        if ttn:
            stmt = stmt.where(ErrorLog.ttn.ilike(f"{ttn}%"))
        stmt = stmt.order_by(ErrorLog.datetime.desc())
        rows = db.execute(stmt).scalars().all()
        return rows
    finally:
        db.close()


@app.post("/add_error")
def add_error(payload: AddErrorIn, _: dict = Depends(require_write)):
    db = get_session()
    try:
        err = ErrorLog(
            user_name=payload.user_name,
            boxid=payload.boxid,
            ttn=payload.ttn,
            datetime=datetime.now(),
            error_message=payload.message
        )
        db.add(err)
        db.commit()
        return {"status": "error_logged"}
    finally:
        db.close()


@app.delete("/delete_error/{error_id}")
def delete_error(error_id: int, _: dict = Depends(require_write)):
    db = get_session()
    try:
        row = db.get(ErrorLog, error_id)
        if not row:
            raise HTTPException(status_code=404, detail="Помилка не знайдена")
        db.delete(row)
        db.commit()
        return {"status": "deleted", "id": error_id}
    finally:
        db.close()


@app.delete("/clear_errors")
def clear_errors(_: dict = Depends(require_admin_or_error_access)):
    db = get_session()
    try:
        db.execute(text("DELETE FROM errors"))
        db.commit()
        return {"status": "errors_cleared"}
    finally:
        db.close()


@app.delete("/clear_tracking")
def clear_tracking(_: dict = Depends(require_admin)):
    db = get_session()
    try:
        db.execute(text("DELETE FROM tracking"))
        db.commit()
        return {"status": "tracking_cleared"}
    finally:
        db.close()


@app.get("/help", response_model=HelpGetOut)
def get_help(_: dict = Depends(require_read)):
    db = get_session()
    try:
        row = db.get(HelpInfo, 1)
        if not row:
            row = HelpInfo(id=1, text_content="Поки що інструкція відсутня.")
            db.add(row)
            db.commit()
            db.refresh(row)
        return HelpGetOut(text_content=row.text_content)
    finally:
        db.close()


@app.post("/help")
def set_help(payload: HelpSetIn, _: dict = Depends(require_admin)):
    db = get_session()
    try:
        row = db.get(HelpInfo, 1)
        if not row:
            row = HelpInfo(id=1, text_content=payload.text_content)
            db.add(row)
        else:
            row.text_content = payload.text_content
        db.commit()
        return {"status": "help_updated"}
    finally:
        db.close()


@app.delete("/purge_all")
def purge_all(_: dict = Depends(require_admin)):
    """
    Полная очистка всех данных (доступ только админу)
    """
    db = get_session()
    try:
        db.execute(text("TRUNCATE TABLE tracking, errors RESTART IDENTITY CASCADE"))
        db.commit()
        return {"status": "all_data_cleared"}
    finally:
        db.close()
