from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import PrimaryKeyConstraint

Base = declarative_base()

class Bookmark(Base):
    __tablename__ = "bookmarks"

    neighborhood = Column(String(50), nullable=False)
    user_name = Column(String(50), nullable=False)
    age = Column(Integer, nullable=False)
    gender = Column(String(10), nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint('neighborhood', 'user_name'),
    )

