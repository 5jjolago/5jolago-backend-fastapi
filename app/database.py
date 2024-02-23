from urllib.parse import quote
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from .models import Base
from kubernetes import client, config
import base64

config.load_incluster_config()
v1 = client.CoreV1Api()
# 시크릿 데이터를 가져옵니다.
sec_data = v1.read_namespaced_secret("mysql-secret", "default").data

# base64로 인코딩된 데이터를 디코딩합니다.
decoded_data = {key: base64.b64decode(value).decode('utf-8') for key, value in sec_data.items()}
print(decoded_data)
# "dbhost" 값을 출력합니다.
user = decoded_data.get("username")
pwd = decoded_data.get("userpass")
host = decoded_data.get("dbhost")
port = 3306
print("DB Host:", host)
print("user: " ,user)
print("password: ",pwd)

db_url = f'mysql+pymysql://{user}:{quote(pwd)}@{host}:{port}/bookmarks'

ENGINE = create_engine(db_url, echo=True)

SessionLocal = scoped_session(
    sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=ENGINE
    )
)

Base.query = SessionLocal.query_property()
Base.metadata.create_all(bind=ENGINE)