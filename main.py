from datetime import datetime, timedelta
from typing import Annotated
import json
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from pymongo import MongoClient
import requests
from requests.utils import dict_from_cookiejar

client = MongoClient("mongodb://localhost:27017/")
db = client["myDatabase"]

# authorization based on fastapi documentation
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# this is used for easier testing
fake_users_db = {
    "admin": {
        "username": "admin",
        "full_name": "Moein Hedayati",
        "email": "moein.hedayati@gmail.com",
        # plain password is 'secret'
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


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


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user

# End of authorization section
# ----------------------------


@app.post("/instagramlogin")
def login(username: str, password: str):

    url = 'https://www.instagram.com/'

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/109.0.5414.120 Safari/537.36",
        "referer": "https://www.instagram.com/"
    }

    with requests.session() as s:
        response = s.get(url+'api/v1/public/landing_info/', headers=headers)
        time = int(datetime.now().timestamp())
        payload = {
            'username': username,
            # password needs to be encoded before being submitted, but I don't know how it's encrypted
            'enc_password': f'#PWD_INSTAGRAM_BROWSER:10:{time}:{password}',
            'queryParams': {},
            'trustedDeviceRecords': {},
            'optIntoOneTap': 'false',
        }
        login_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/109.0.5414.120 Safari/537.36",
            "referer": "https://www.instagram.com/",
            'X-Csrftoken': dict_from_cookiejar(response.cookies)['csrftoken']
        }
        login_response = s.post(url+'api/v1/web/accounts/login/ajax/', params=payload, headers=login_headers)
        if login_response.json()['status'] == 'fail':
            return login_response.status_code
        else:
            cookies = login_response.cookies
            account = db["cookies"].insert_one({"username": username, "cookies": dict(cookies)})
            return account.inserted_id


@app.get("/followers/{username}")
def get_followers(username: str):
    url = 'https://www.instagram.com/'
    cookies = db["cookies"].find_one({"username": username})
    if not cookies:
        return {"message": "User not logged in"}
    else:
        with requests.session() as s:
            # getting followers count
            payload = {
                'username': username
            }
            # headers = {
            #     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            #                   "Chrome/109.0.5414.120 Safari/537.36",
            #     "referer": "https://www.instagram.com/"+username+'/',
            #     'X-Csrftoken': cookies['csrftoken']
            # }
            headers = {"Sec-Ch-Ua": "\"Chromium\";v=\"109\", \"Not_A Brand\";v=\"99\"",
                       "X-Ig-App-Id": "936619743392459",
                       "X-Ig-Www-Claim": "hmac.AR2FvMcW1KQHpiMt4UWh6EgYyODl-Ts58DjneH7LSCLbddJH",
                       "Sec-Ch-Ua-Mobile": "?0",
                       "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36",
                       "Viewport-Width": "770", "Accept": "*/*", "Sec-Ch-Ua-Platform-Version": "\"14.0.0\"",
                       "X-Requested-With": "XMLHttpRequest", "X-Asbd-Id": "129477",
                       "Sec-Ch-Ua-Full-Version-List": "\"Chromium\";v=\"109.0.5414.120\", \"Not_A Brand\";v=\"99.0.0.0\"",
                       'X-Csrftoken': cookies['csrftoken'], "Sec-Ch-Prefers-Color-Scheme": "dark",
                       "Sec-Ch-Ua-Platform": "\"Windows\"", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
                       "Sec-Fetch-Dest": "empty", "referer": "https://www.instagram.com/"+username+'/',
                       "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9"}

            follower_response = s.get(url+'api/v1/users/web_profile_info/', params=payload, headers=headers, cookies=cookies)
            follower_count = follower_response.json()['data']['user']['edge_followed_by']['count']

            # get followers
            payload = {
                'count': follower_count,
                'max_id': 'QVFBR2NkTXhsYXBaZjZWMklUd3hVdTNodVhXWmVZYUc1M1FRSUNJLXpfNVkyNkdPRkwtV1FZSWFzbG00UE85T0cwbms2NElvTkFFZWNCNUtMcHU0NVIxaQ%3D%3D',
                'search_surface': 'follow_list_page'
            }
            headers['referer'] = "https://www.instagram.com/" + username + '/followers/'
            followerlist_response = s.get(url+f'api/v1/friendships/{cookies["ds_user_id"]}/followers/', params=payload, headers=headers, cookies=cookies)
            followerlist = {}
            for user in followerlist_response.json()['users']:
                followerlist[user['pk']] = user['username']

            return followerlist
