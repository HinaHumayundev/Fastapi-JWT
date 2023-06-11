import uvicorn
import jwt 
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
import bcrypt
from fastapi.security import HTTPBearer
from fastapi import FastAPI, Depends, HTTPException, Body
from src.schemas import AuthDetails

app = FastAPI()

class AuthBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request):
        auth = await super().__call__(request)
        return auth.credentials


class AuthHandler:
    security = HTTPBearer()
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    secret = "SECRET"

    @staticmethod
    def get_password_hash(password):
        return AuthHandler.pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password, hashed_password):
        return AuthHandler.pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def encode_token(user_id):
        payload = {
            'exp': datetime.utcnow() + timedelta(days=0, minutes=5),
            'iat': datetime.utcnow(),
            'sub': user_id,
        }
        return jwt.encode(payload, AuthHandler.secret, algorithm='HS256')

    @staticmethod
    def decode_token(token):
        try:
            payload = jwt.decode(token, AuthHandler.secret, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Signature has expired')
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail='Invalid token')

    @staticmethod
    def auth_wrapper(auth: HTTPAuthorizationCredentials = Security(security)):
        return AuthHandler.decode_token(auth.credentials)



auth_bearer = AuthBearer()
auth_handler = AuthHandler()
users = []


@app.post('/register', status_code=201)
def register(auth_details: AuthDetails = Body(...)):
    if any(x['username'] == auth_details.username for x in users):
        raise HTTPException(status_code=400, detail='Username is taken')
    hashed_password = auth_handler.get_password_hash(auth_details.password)
    users.append({
        'username': auth_details.username,
        'password': hashed_password    
    })
    return


@app.post('/login')
def login(auth_details: AuthDetails):
    user = None
    for x in users:
        if x['username'] == auth_details.username:
            user = x
            break
    
    if (user is None) or (not auth_handler.verify_password(auth_details.password, user['password'])):
        raise HTTPException(status_code=401, detail='Invalid username and/or password')
    token = auth_handler.encode_token(user['username'])
    return { 'token': token }


@app.get('/unprotected')
def unprotected():
    return { 'hello': 'world' }


@app.get('/protected')
def protected(username=Depends(AuthHandler.auth_wrapper)):
    return { 'name': username }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
