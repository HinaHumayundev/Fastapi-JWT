import jwt 
from fastapi import HTTPException, Security
from fastapi.secuirty import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta

class AuthHandler():
    security = HTTPBearer()
    pwd_context = CryptContext(schemes=["bcrypt"],deprecated="auto")
    secret="SECRET"

def get_password_hash(self,password):
    return self.pwd_context.hash(password)

def verify_password(self, plain_password, hashed_password):
    return self.pwd_context.verify(plain_password, hashed_password)

def encode_token(self, user_id):
    payload = {
        'exp' : datetime.utcnow() + timedelta(days=0,minutes=5),
        'iat' : datetime.utcnow(),
        'sub' : user_id,
    }
    return jwt.encode (
        payload,
        self.secret,
        algorithm= 'HS256'
    )


