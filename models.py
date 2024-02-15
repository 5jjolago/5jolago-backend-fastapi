from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import PrimaryKeyConstraint

Base = declarative_base()

class Bookmark(Base):
    __tablename__ = "bookmarks"

    neighborhood = Column(String, nullable=False)
    user_name = Column(String, nullable=False)
    age = Column(Integer, nullable=False)
    gender = Column(String, nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint('neighborhood', 'user_name'),
    )
