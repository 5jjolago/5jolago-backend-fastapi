from pydantic import BaseModel


class Bookmark(BaseModel):
    neighborhood: str
    user_name: str
    age: str
    gender: str

    class Config:
        orm_mode = True
