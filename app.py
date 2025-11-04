from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Optional, List

from dotenv import load_dotenv
from fastapi import FastAPI, Query, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import create_engine, select, func, and_, text
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

app = FastAPI(title="TrackingApp API", version="1.1")

# ---------------------- Авторизация ----------------------
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"

PASSWORDS = {
    "301993": 1,      # админ
    "123123123": 0,   # пользователь (может очищать ошибки, но не историю)
    "321321321": 2    # только просмотр
}

security = HTTPBearer()

def create_token(level: int) -> str:
    payload = {
        "level": level,
        "exp": datetime.utcnow() + timedelta(hours=12)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> int:
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        level = payload.get("level")
        if level is None:
            raise HTTPException(status_code=401, detail="Невірний токен")
        return int(level)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Термін дії токена минув")
    except Exception:
        raise HTTPException(status_code=401, detail="Невірний або протермінований токен")

def require_admin(level: int = Depends(verify_token)):
    if level != 1:
        raise HTTPException(status_code=403, detail="Доступ тільки для адміністратора")
    return level

def require_write(level: int = Depends(verify_token)):
    if level not in (0, 1):
        raise HTTPException(status_code=403, detail="Недостатньо прав для цієї дії")
    return level

def require_admin_or_error_access(level: int = Depends(verify_token)):
    if level not in (0, 1):
        raise HTTPException(status_code=403, detail="Недостатньо прав для цієї дії")
    return level

def require_read(level: int = Depends(verify_token)):
    return level

@app.post("/login")
def login(password: str = Query(..., description="Пароль доступу")):
    if password not in PASSWORDS:
        raise HTTPException(status_code=401, detail="Невірний пароль")
    level = PASSWORDS[password]
    token = create_token(level)
    return {"token": token, "access_level": level}

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

with engine.begin() as conn:
    Base.metadata.create_all(conn)
    conn.execute(text("""
        INSERT INTO help_info (id, text_content)
        VALUES (1, 'Поки що інструкція відсутня. Натисніть «Добавить/Изменить инструкцію», щоб додати.')
        ON CONFLICT (id) DO NOTHING
    """))
    conn.execute(text("""
        INSERT INTO settings (id, auto_export, auto_save, export_directory)
        VALUES (1, FALSE, TRUE, '')
        ON CONFLICT (id) DO NOTHING
    """))

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


# ---------------------- Эндпоинты ----------------------
@app.get("/")
def root():
    return {"status": "online", "message": "TrackingApp API працює"}

@app.post("/add_record", response_model=AddRecordOut)
def add_record(payload: AddRecordIn, level: int = Depends(require_write)):
    db = get_session()
    try:
        note, exists_exact, exists_box, exists_ttn = check_duplicates(db, payload.boxid, payload.ttn)

        # Всегда пишем в историю
        rec = Tracking(
            user_name=payload.user_name,
            boxid=payload.boxid,
            ttn=payload.ttn,
            datetime=datetime.utcnow(),
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
                datetime=datetime.utcnow(),
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
    level: int = Depends(require_read)
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
    level: int = Depends(require_read)
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
def add_error(payload: AddErrorIn, level: int = Depends(require_write)):
    db = get_session()
    try:
        err = ErrorLog(
            user_name=payload.user_name,
            boxid=payload.boxid,
            ttn=payload.ttn,
            datetime=datetime.utcnow(),
            error_message=payload.message
        )
        db.add(err)
        db.commit()
        return {"status": "error_logged"}
    finally:
        db.close()

@app.delete("/delete_error/{error_id}")
def delete_error(error_id: int, level: int = Depends(require_write)):
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
def clear_errors(level: int = Depends(require_admin_or_error_access)):
    db = get_session()
    try:
        db.execute(text("DELETE FROM errors"))
        db.commit()
        return {"status": "errors_cleared"}
    finally:
        db.close()

@app.delete("/clear_tracking")
def clear_tracking(level: int = Depends(require_admin)):
    db = get_session()
    try:
        db.execute(text("DELETE FROM tracking"))
        db.commit()
        return {"status": "tracking_cleared"}
    finally:
        db.close()

@app.get("/help", response_model=HelpGetOut)
def get_help(level: int = Depends(require_read)):
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
def set_help(payload: HelpSetIn, level: int = Depends(require_admin)):
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
def purge_all(level: int = Depends(require_admin)):
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
