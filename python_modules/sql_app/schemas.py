from pydantic import BaseModel


class ItemBase(BaseModel):
    title: str
    description: str | None = None


class ItemCreate(ItemBase):
    pass


class Item(ItemBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    username: str
    email: str
    password: str

class UserResponse(UserBase):
    id: int
    username: str
    email: str | None = None
    is_active: bool
    items: list[Item] = []
    
class User(UserBase):
    id: int
    username: str
    hashed_password: str
    email: str | None = None
    is_active: bool
    items: list[Item] = []

    class Config:
        orm_mode = True

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None

