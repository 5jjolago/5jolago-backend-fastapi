from urllib.parse import quote
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

user = "admin"
pwd = "qwer1234"
host = "mysql.cd2mgo42smp1.ap-northeast-2.rds.amazonaws.com"
port = 3306
db_url = f'mysql+pymysql://{user}:{quote(pwd)}@{host}:{port}/bookmarks'



ENGINE = create_engine(db_url, echo=True)

SessionLocal = scoped_session(
    sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=ENGINE
    )
)

Base = declarative_base()
Base.query = SessionLocal.query_property()
Base.metadata.create_all(bind=ENGINE)