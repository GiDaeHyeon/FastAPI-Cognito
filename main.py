from fastapi import FastAPI, Request, Depends, Header
from fastapi.responses import JSONResponse

from utils.auth import JWTBearer


app = FastAPI()
auth = JWTBearer()


@app.get("/ping")
async def root() -> JSONResponse:
    return JSONResponse(content={"message": "pong"}, status_code=200)


@app.get('/login')
async def login(request: Request, user_name: str, password: str) -> JSONResponse:
    tokens = 'tokens', auth.login(user_name=user_name, password=password)
    return JSONResponse(content=tokens, status_code=200)


@app.get("/auth-test", dependencies=[Depends(auth)])
async def auth_test(request: Request) -> JSONResponse:
    return JSONResponse(content={'message': True}, status_code=200)
