from typing import Dict, Optional, List
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode
from pydantic import BaseModel, ConfigDict, validator
from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session
from .database import SessionLocal, ENGINE
from app import models,schemas
from starlette.middleware.cors import CORSMiddleware
import requests
from sqlalchemy.exc import IntegrityError
from redis import Redis
import json

# FastAPI 애플리케이션 생성
app = FastAPI()

# Redis 연결 설정
redis_client = Redis(
    host='redis-svc.default.svc.cluster.local',
    port=6379,
    db=0,
    ssl=True,  # TLS를 사용하는 경우
    ssl_cert_reqs=None,
    decode_responses=True
)


@app.on_event("startup")
async def startup_event():
    # Redis 서버에 연결 시도
    try:
        redis_client.ping()
        print("Connected to Redis")
    except Exception as e:
        print(f"Redis connection error: {e}")



# cors 설정
origins = [
    "http://www.nalraon.kr",
    "https://www.nalraon.kr",
    "http://www.nalraon.kr/",
    "https://www.nalraon.kr/",
    # "http://fastapi-svc:8080"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS", "DELETE"],
    allow_headers=["*"],
)


JWK = Dict[str, str]

#JWKS 모델 정의
class JWKS(BaseModel):
    keys: List[JWK]

# JWT 인증 정보 모델 정의 
class JWTAuthorizationCredentials(BaseModel):
    jwt_token: str
    header: Dict[str, str]
    claims: Dict[str, str]
    signature: str
    message: str

# JWKS 가져오는 함수 정의 
# AWS Cognito 사용자 풀에 대한 공개 키를 얻어옴 
# 환경변수화 해야함 
def get_jwks() -> JWKS:
    return requests.get(
        # f"https://cognito-idp.{os.environ.get('COGNITO_REGION')}.amazonaws.com/"
        # f"{os.environ.get('COGNITO_POOL_ID')}/.well-known/jwks.json"
        "https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_LfAalhnRP/.well-known/jwks.json"
    ).json()


# JWTBearer 클래스 정의 
class JWTBearer(HTTPBearer):
    def __init__(self, jwks: JWKS, auto_error: bool = True):
        super().__init__(auto_error=auto_error)
        self.kid_to_jwk = {jwk["kid"]: jwk for jwk in jwks['keys']}
        
		# JWT 토큰 검증 함수 
    def verify_jwk_token(self, jwt_credentials: JWTAuthorizationCredentials) -> bool:
        try:
            public_key = self.kid_to_jwk[jwt_credentials.header["kid"]]
        except KeyError:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="JWK public key not found"
            )

        key = jwk.construct(public_key)
        decoded_signature = base64url_decode(jwt_credentials.signature.encode())

        return key.verify(jwt_credentials.message.encode(), decoded_signature)
		# 요청 처리 함수 
    async def __call__(self, request: Request) -> Optional[JWTAuthorizationCredentials]:
        credentials: HTTPAuthorizationCredentials = await super().__call__(request)

        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Wrong authentication method"
                )

            jwt_token = credentials.credentials
            message, signature = jwt_token.rsplit(".", 1)

            try:
                # claims의 각 속성이 str형태여야 함 
                jwt_claims = jwt.get_unverified_claims(jwt_token)
                jwt_claims['auth_time'] = str(jwt_claims['auth_time'])
                jwt_claims['exp'] = str(jwt_claims['exp'])
                jwt_claims['iat'] = str(jwt_claims['iat'])
                jwt_credentials = JWTAuthorizationCredentials(
                    jwt_token=jwt_token,
                    header=jwt.get_unverified_header(jwt_token),
                    claims=jwt_claims,
                    signature=signature,
                    message=message,
                )
            except JWTError:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="JWK invalid1")

            if not self.verify_jwk_token(jwt_credentials):
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="JWK invalid2")

            return jwt_credentials
        
        
# JWTBearer 인스턴스 생성
jwks = get_jwks()
jwt_bearer = JWTBearer(jwks)

# JWT에서 사용자 이름 추출 함수 
async def get_current_user(
    credentials: JWTAuthorizationCredentials = Depends(jwt_bearer)
) -> str:
    try:
        return credentials.claims["username"]
    except KeyError:
        HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Username missing")

# 데이터베이스 세션 생성 함수
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 사용자별 북마크 가져오기 엔드포인트 
# @app.get("/bookmarks/", dependencies=[Depends(jwt_bearer)],response_model=List[schemas.Bookmark])
# async def get_bookmarks(user_name: str = Depends(get_current_user), db: Session = Depends(get_db)):
#     """
#     username에 해당하는 모든 북마크를 가져오는 엔드포인트.
#     """
#     bookmarks = db.query(models.Bookmark).filter(models.Bookmark.user_name == user_name).all()
#     if not bookmarks:
#         raise HTTPException(status_code=404, detail="Bookmark not found")
#     return bookmarks


# 새 북마크를 생성하는 엔드포인트
@app.post("/bookmarks/", dependencies=[Depends(jwt_bearer)], response_model=schemas.Bookmark)
async def create_bookmark(
    neighborhood: str,
    age: int,
    gender: str,
    user_name: str = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    new_bookmark = models.Bookmark(neighborhood=neighborhood, user_name=user_name, age=age, gender=gender)
    db.add(new_bookmark)

    try:
        db.commit()
        db.refresh(new_bookmark)
        # Redis 캐시 업데이트
        cache_key = f"bookmarks:{user_name}"
        cached_bookmarks = redis_client.get(cache_key)
        
        if cached_bookmarks:
            # 캐시된 북마크가 있다면, 새 북마크 데이터를 추가합니다.
            bookmarks = json.loads(cached_bookmarks)
            # Bookmark 인스턴스를 사전으로 변환하여 추가합니다.
            bookmarks.append(schemas.Bookmark.from_orm(new_bookmark).dict())
            redis_client.setex(cache_key, 3600, json.dumps(bookmarks))
        else:
            # 캐시된 북마크가 없다면, DB에서 북마크 목록을 다시 로드하고 캐시합니다.
            bookmarks = db.query(models.Bookmark).filter(models.Bookmark.user_name == user_name).all()
            bookmarks_data = [schemas.Bookmark.from_orm(bookmark).dict() for bookmark in bookmarks]
            redis_client.setex(cache_key, 3600, json.dumps(bookmarks_data))
    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="Could not create bookmark")
    
    return new_bookmark



# 사용자 탈퇴로 인한 북마크 삭제하기 
@app.delete("/bookmarks/", dependencies=[Depends(jwt_bearer)])
async def delete_bookmark_endpoint(user_name: str = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    주어진 북마크 ID에 해당하는 북마크를 삭제하는 엔드포인트.
    """
    # 데이터베이스에서 해당 북마크를 가져옵니다.
    bookmarks = db.query(models.Bookmark).filter(models.Bookmark.user_name == user_name).all()
    if not bookmarks:
        # 만약 해당 ID에 해당하는 북마크가 없다면 HTTPException을 발생시킵니다.
        raise HTTPException(status_code=404, detail="Bookmark not found")
    
    # 데이터베이스에서 해당 사용자의 모든 북마크를 삭제합니다.
    for bookmark in bookmarks:
        db.delete(bookmark)
    db.commit()

     # 삭제에 성공했음을 알리는 메시지를 반환합니다.
    return {"message": "Bookmark deleted successfully"}

# 북마크 삭제하기  
@app.delete("/bookmarks/{neighborhood}", dependencies=[Depends(jwt_bearer)])
async def delete_bookmark_endpoint( neighborhood: str,user_name: str = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    주어진 북마크 ID에 해당하는 북마크를 삭제하는 엔드포인트.
    """
    # 데이터베이스에서 해당 북마크를 가져옵니다.
    bookmark = db.query(models.Bookmark).filter(models.Bookmark.user_name == user_name , models.Bookmark.neighborhood == neighborhood).first()
    if not bookmark:
        # 만약 해당 ID에 해당하는 북마크가 없다면 HTTPException을 발생시킵니다.
        raise HTTPException(status_code=404, detail="Bookmark not found")
    
    # 데이터베이스에서 해당 북마크를 삭제합니다.
    db.delete(bookmark)
    db.commit()

    cache_key = f"bookmarks:{user_name}"
    redis_client.delete(cache_key)

     # 삭제에 성공했음을 알리는 메시지를 반환합니다.
    return {"message": "Bookmark deleted successfully"}




@app.get("/bookmarks/",dependencies=[Depends(jwt_bearer)])
async def get_bookmarks(user_name: str = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    username에 해당하는 모든 북마크를 가져오는 엔드포인트.
    Redis를 사용하여 캐싱 처리를 합니다.
    """
    # Redis에서 캐시된 데이터를 조회
    cache_key = f"bookmarks:{user_name}"
    cached_bookmarks = redis_client.get(cache_key)

    if cached_bookmarks:
        # 캐시된 데이터가 있으면 JSON으로 변환하여 반환
        print("cached : ",json.loads(cached_bookmarks))
        return json.loads(cached_bookmarks)

    # DB에서 데이터 조회
    bookmarks = db.query(models.Bookmark).filter(models.Bookmark.user_name == user_name).all()
    print("not cached: ",bookmarks)
    if not bookmarks:
        raise HTTPException(status_code=404, detail="Bookmark not found")
    
    # 조회 결과를 JSON으로 변환
    bookmarks_data = [schemas.Bookmark.from_orm(bookmark).dict() for bookmark in bookmarks]
    
    # Redis에 데이터 캐싱 (예: 1시간 동안 유효)
    redis_client.setex(cache_key, 3600, json.dumps(bookmarks_data))
    
    return bookmarks_data

