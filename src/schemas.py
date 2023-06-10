from pydantic import BaseModel

class AuthDetails(BaseModel):
    username: str
    passwords: str