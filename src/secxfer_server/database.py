from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    key_id = Column(String, primary_key=True)
    identity_pubkey = Column(String, nullable=False) # hex-encoded 64 bytes
    
    prekeys = relationship("PreKey", back_populates="user", cascade="all, delete-orphan")

class PreKey(Base):
    __tablename__ = "prekeys"
    
    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.key_id"), nullable=False)
    pubkey = Column(String, nullable=False) # hex-encoded 32 bytes
    
    user = relationship("User", back_populates="prekeys")

SQLALCHEMY_DATABASE_URL = "sqlite:///./secxfer.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
