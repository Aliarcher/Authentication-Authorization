from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.param_functions import Form
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import uvicorn
import pytz
import uvicorn
import requests
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI()




# from fastapi_jwt_auth import AuthJWT
# from fastapi_jwt_auth.exceptions import AuthJWTException
#pip install python-jose
#pip install passlib
#pip install bcrypt

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 200     # expire the token, even though user has not logged out. Change the time for your testing.
REFRESH_TOKEN_EXPIRE_SECONDS=2000000
utc=pytz.UTC

#user -> ali
#password -> secret

fake_users_db = {
    "ali": {
        "username": "ali",
        "full_name": "Seyed Ali Mir Mohammad Hoseini",
        "email": "SeyedAli@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
    "ravi": {
        "username": "ravi",
        "full_name": "ravi singh",
        "email": "ravi.singh@gmail.com",
        "hashed_password": "$2b$12$ODf2vUEfanF3P1JykF0CgO7jafMA9RWCuqZxLUAqCcQJ1FYxxFROC",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },    
}


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class RefreshToken(BaseModel):
    refresh_token: str

class TokenData(BaseModel):
    username: Optional[str] = None
    expires: datetime

class OAuth2Form:
    grant_type: str = Form(default=None, regex="password"),
    username: str = Form(),
    password: str = Form(),


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["*"] 
)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()

    expire = datetime.utcnow() + expires_delta

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt



# get the current user from auth token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    # define credential exception
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # decode token and extract username and expires data
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        exps:int = payload.get("exp")

        # validate username
        if username is None:
            raise credentials_exception

        token_data = TokenData(username=username, expires=exps)  # exps of int is converted to datetime type
    except JWTError:
        raise credentials_exception

    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception

    # check token expiration
    if exps is None:
        raise credentials_exception
    #TODO:check if user exist and token expired raise 401 error to client side  
    # if user is not None and exps is None:
        #raise HTTPException(status_code=401, detail="token expired")
    if utc.localize(datetime.utcnow()) > token_data.expires:
        print("Token is expired.\n")
        #raise credentials_exception  
        raise HTTPException(status_code=401, detail="token expired")     
 
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):  # login function to get access token
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    refresh_token_expires = timedelta(seconds=REFRESH_TOKEN_EXPIRE_SECONDS)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    refresh_token =create_refresh_token(
        data={"sub": user.username}, expires_delta=refresh_token_expires
    )
    return {"access_token": access_token,"refresh_token": refresh_token,"token_type": "bearer"}



@app.post("/refresh",response_model=Token)
async def refresh(refresh_token:str):
    #Decode refresh token
    decoded_refresh_token=jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

    #TODO:get user by refresh token
    user=decoded_refresh_token.get("sub")
    #TODO:create new access token for that user
    access_token_expires = timedelta(seconds=ACCESS_TOKEN_EXPIRE_SECONDS)
    access_token=create_access_token(
        data={"sub": user}, expires_delta=access_token_expires
    )

    return {"access_token": access_token,"refresh_token": refresh_token,"token_type": "bearer"}




@app.delete("/logout", response_model=Token)
async def logout(current_user: User = Depends(get_current_active_user)):  # logout function to delete access token
    token_data = TokenData(username=current_user.username, expires=0)
    return token_data
    #return "User logout sucessful." 

 


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]



@app.get("/protected_hi")
async def protected_hi(current_user: User = Depends(get_current_active_user)):
    return f"Hi {current_user.username}! How are you? You are in a protected Zone."


@app.get("/unprotected_hi")
async def unprotected_hi():
    return "Hi! How are you? You are in an un-protected Zone."



if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5002)