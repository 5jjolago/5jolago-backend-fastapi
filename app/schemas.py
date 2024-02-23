from pydantic import BaseModel


class Bookmark(BaseModel):
    neighborhood: str
    user_name: str
    age: int
    gender: str

    class Config:
        orm_mode = True
        from_attributes = True
