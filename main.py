from typing import Dict, Optional, List
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode
from pydantic import BaseModel, ConfigDict, validator
from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from models import Bookmark
from starlette.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "http://127.0.0.1:3000",
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


JWK = Dict[str, str]


class JWKS(BaseModel):
    keys: List[JWK]


class JWTAuthorizationCredentials(BaseModel):
    jwt_token: str
    header: Dict[str, str]
    claims: Dict[str, str]
    signature: str
    message: str

    # @validator('claims')
    # def validate_claims(cls, value):
    #     value['auth_time'] = str(value.get('auth_time'))
    #     value['exp'] = str(value.get('exp'))
    #     value['iat'] = str(value.get('iat'))
    #     return value

# 새 북마크를 나타내는 Pydantic 스키마
class BookmarkCreate(BaseModel):
    url: str
    title: str

import requests

def get_jwks() -> JWKS:
    return requests.get(
        # f"https://cognito-idp.{os.environ.get('COGNITO_REGION')}.amazonaws.com/"
        # f"{os.environ.get('COGNITO_POOL_ID')}/.well-known/jwks.json"
        "https://cognito-idp.ap-northeast-2.amazonaws.com/ap-northeast-2_LfAalhnRP/.well-known/jwks.json"
    ).json()

jwks = get_jwks()


class JWTBearer(HTTPBearer):
    def __init__(self, jwks: JWKS, auto_error: bool = True):
        super().__init__(auto_error=auto_error)
        # print({jwk["kid"]: jwk for jwk in jwks['keys']})
        self.kid_to_jwk = {jwk["kid"]: jwk for jwk in jwks['keys']}
        

    def verify_jwk_token(self, jwt_credentials: JWTAuthorizationCredentials) -> bool:
        try:
            # print(JWTAuthorizationCredentials.header["kid"])
            print(jwt_credentials.header["kid"])
            # print(self.kid_to_jwk['eUCbi7dyK+gm4PHbBz8f8vyuMJmq4NnTAlklH3jeUVM='])
            public_key = self.kid_to_jwk[jwt_credentials.header["kid"]]
        except KeyError:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="JWK public key not found"
            )

        key = jwk.construct(public_key)
        decoded_signature = base64url_decode(jwt_credentials.signature.encode())

        return key.verify(jwt_credentials.message.encode(), decoded_signature)

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
jwt_bearer = JWTBearer(jwks)

# 데이터베이스 세션 생성 함수
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 사용자별 북마크 가져오기 
@app.get("/bookmarks/{user_name}", dependencies=[Depends(jwt_bearer)])
async def get_bookmarks(user_name: str, db: Session = Depends(get_db)):
    """
    username에 해당하는 모든 북마크를 가져오는 엔드포인트.
    """
    bookmarks = db.query(Bookmark).filter(Bookmark.user_name == user_name).all()
    if not bookmarks:
        raise HTTPException(status_code=404, detail="Bookmark not found")
    return bookmarks


# 새 북마크를 생성하는 엔드포인트
@app.post("/bookmarks/", dependencies=[Depends(jwt_bearer)])
async def create_bookmark(
    neighborhood: str,
    user_name: str,
    age: int,
    gender: str,
    db: Session = Depends(get_db)
):
    """
    새 북마크를 생성하는 엔드포인트.
    """
    # 새로운 북마크를 생성하여 데이터베이스에 추가
    new_bookmark = Bookmark(neighborhood=neighborhood, user_name=user_name, age=age, gender=gender)
    db.add(new_bookmark)
    db.commit()
    db.refresh(new_bookmark)
    
    # 생성된 북마크를 반환
    return new_bookmark

# 사용자 탈퇴로 인한 북마크 삭제하기 
@app.delete("/bookmarks/{user_name}", dependencies=[Depends(jwt_bearer)])
async def delete_bookmark_endpoint(user_name: str, db: Session = Depends(get_db)):
    """
    주어진 북마크 ID에 해당하는 북마크를 삭제하는 엔드포인트.
    """
    # 북마크를 삭제합니다.
    # 데이터베이스에서 해당 북마크를 가져옵니다.
    bookmark = db.query(Bookmark).filter(Bookmark.user_name == user_name).first()
    if not bookmark:
        # 만약 해당 ID에 해당하는 북마크가 없다면 HTTPException을 발생시킵니다.
        raise HTTPException(status_code=404, detail="Bookmark not found")
    
    # 데이터베이스에서 해당 북마크를 삭제합니다.
    db.delete(bookmark)
    db.commit()

     # 삭제에 성공했음을 알리는 메시지를 반환합니다.
    return {"message": "Bookmark deleted successfully"}

# 북마크 삭제하기  
@app.delete("/bookmarks/{user_name}/{neighborhood}", dependencies=[Depends(jwt_bearer)])
async def delete_bookmark_endpoint(user_name: str, neighborhood: str, db: Session = Depends(get_db)):
    """
    주어진 북마크 ID에 해당하는 북마크를 삭제하는 엔드포인트.
    """
    # 북마크를 삭제합니다.
    # 데이터베이스에서 해당 북마크를 가져옵니다.
    bookmark = db.query(Bookmark).filter(Bookmark.user_name == user_name , Bookmark.neighborhood == neighborhood).first()
    if not bookmark:
        # 만약 해당 ID에 해당하는 북마크가 없다면 HTTPException을 발생시킵니다.
        raise HTTPException(status_code=404, detail="Bookmark not found")
    
    # 데이터베이스에서 해당 북마크를 삭제합니다.
    db.delete(bookmark)
    db.commit()

     # 삭제에 성공했음을 알리는 메시지를 반환합니다.
    return {"message": "Bookmark deleted successfully"}
