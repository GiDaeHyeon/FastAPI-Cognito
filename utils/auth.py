import os
import boto3
import requests

from fastapi import HTTPException, Request
from fastapi.security import HTTPBearer

from pydantic import BaseModel

from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode

from typing import Dict, List, Optional


JWK = Dict[str, str]


class JWKS(BaseModel):
    keys: List[JWK]


class JWTAuthorizationCredentials(BaseModel):
    jwt_token: str
    header: Dict[str, str]
    claims: Dict[str, str]
    signature: str
    message: str


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True, aws_region: str = AWS_REGION, pool_id: str = POOL_ID,
                 client_id: str = CLIENT_ID) -> None:
        """
        일반적으로 토큰 인증 방식 Auth 경우 header의 Authorization Key에 토큰을 담아 요청을 보냅니다. 그 형식은 아래와 같습니다.
        {Authorization: JWTTokenBlahBlah}
        FastAPI의 HTTPBearer는 Header의 Token을 찾아 여러 기본적 처리를 수행합니다. 여기에서는 AWS의 Cognito를 활용한 OAuth2 인증을 수행할
        것이므로, HTTPBearer를 상속받아 JWT Auth 관련 메서드를 추가했습니다.

        :param auto_error:
        :param aws_region:
        :param pool_id:
        """
        super(JWTBearer, self).__init__(auto_error=auto_error)
        self.aws_region = os.environ.get('AWS_REGION', None)
        self.pool_id = os.environ.get('POOL_ID', None)
        self.client_id = os.environ.get('CLIENT_ID', None)
        self.jwks = self.get_jwks()
        self.kid_to_jwk = {_jwk['kid']: _jwk for _jwk in self.jwks.keys}

    def get_jwks(self) -> JWKS:
        if self.aws_region is None or self.pool_id is None:
            raise ValueError('Some env variables are "None". Please check the envs.')

        resp = requests.get(f'https://cognito-idp.{self.aws_region}.amazonaws.com/{self.pool_id}/.well-known/jwks.json')

        if resp.status_code != 200:
            raise ConnectionError('Getting jwk is failed.')

        return JWKS.parse_obj(resp.json())

    def verify_jwk_token(self, jwt_credentials: JWTAuthorizationCredentials) -> bool:
        try:
            public_key = self.kid_to_jwk[jwt_credentials.header.get('kid', None)]
        except KeyError:
            raise HTTPException(status_code=403, detail="JWK public key not found.")

        key = jwk.construct(public_key)
        decoded_signature = base64url_decode(jwt_credentials.signature.encode())
        return key.verify(jwt_credentials.message.encode(), decoded_signature)

    async def __call__(self, request: Request) -> Optional[JWTAuthorizationCredentials]:
        credentials = await super(JWTBearer, self).__call__(request=request)
        if credentials:
            if not credentials.scheme == 'Bearer':
                raise HTTPException(status_code=403, detail="Wrong auth method")

            jwt_token = credentials.credentials
            message, signature = jwt_token.rsplit('.', 1)

            try:
                jwt_credentials = JWTAuthorizationCredentials(
                    jwt_token=jwt_token,
                    header=jwt.get_unverified_header(jwt_token),
                    claims=jwt.get_unverified_claims(jwt_token),
                    signature=signature,
                    message=message
                )
            except JWTError:
                raise HTTPException(status_code=403, detail='Invalid JWK')

            if not self.verify_jwk_token(jwt_credentials=jwt_credentials):
                raise HTTPException(status_code=403, detail='Invalid JWK')

            return jwt_credentials

    def login(self, user_name: str, password: str) -> Dict:
        idp_client = boto3.client('cognito-idp', 'ap-northeast-2', aws_access_key_id=os.environ.get('AWS_ACCESS_KEY'),
                                  aws_secret_access_key=os.environ.get('AWS_SECRET_KEY'))
        resp = idp_client.admin_initiate_auth(UserPoolId=self.pool_id,
                                              ClientId=self.client_id,
                                              AuthFlow='ADMIN_NO_SRP_AUTH',
                                              AuthParameters={'USERNAME': user_name, 'PASSWORD': password})
        return resp['AuthenticationResult']
