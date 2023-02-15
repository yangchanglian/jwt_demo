import datetime
import uuid
from rest_framework.views import APIView
from rest_framework.response import Response
from api.extensions.auth import JwtQueryParmsAuthentication
from api.utils.jwt_auth import create_token
from api import models


class LoginView(APIView):
    """用户登录"""

    def post(self,request,*args,**kwargs):
        user = request.data.get('username')
        pwd = request.data.get('password')

        user_object = models.UserInfo.objects.filter(username=user,password=pwd).first()
        if not user_object:
            return Response({'code':1000,'error':'用户名或密码错误'})
        random_string = str(uuid.uuid4())
        user_object.token = random_string
        user_object.save()
        return Response({'code':1001,'data':random_string})

class OrderView(APIView):
    def get(self,request,*args,**kwargs):
        token = request.query_params.get('token')
        if not token:
            return Response({'code':2000,'error':"登录成功之后才能访问"})
        user_object = models.UserInfo.objects.filter(token=token).first()
        if not user_object:
            Response({'code': 2000, 'error': "token无效"})
        return Response({'code': 201,'data':'订单列表'})

class JwtLoginView(APIView):
    """基于jwt用户登录"""

    def post(self,request,*args,**kwargs):
        user = request.data.get('username')
        pwd = request.data.get('password')

        user_object = models.UserInfo.objects.filter(username=user,password=pwd).first()
        if not user_object:
            return Response({'code':1000,'error':'用户名或密码错误'})
        import jwt
        import datetime
        salt = "sjgfjsbflkshflsjfliuhuihkjvksb2323knkf4"
        # 构造header
        headers = {
            'typ':'jwt',
            'alg':'HS256'
        }
        # 构造payload
        payload = {
            'user_id': 1,# 自定义用户ID
            'username':'wupeiqi',# 自定义用户名
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5) # 超时时间

        }
        token = jwt.encode(payload=payload,key=salt,algorithm='HS256',headers=headers)
        return Response({'code':1001,'data':token})

class JwtOrderView(APIView):
    def get(self,request,*args,**kwargs):
        # 获取 token 并判断token的合法性
        token = request.query_params.get('token')
        # 1.切割
        # 2. 解密第二段/判断过期
        # 3.验证第三段合法性
        import jwt
        from jwt import exceptions
        salt = "sjgfjsbflkshflsjfliuhuihkjvksb2323knkf4"
        payload = None
        msg = None
        try:
            payload = jwt.decode(token, salt,algorithms='HS256')

        except exceptions.ExpiredSignatureError:
            msg = "token已失效"
        except jwt.DecodeError:
            msg = "token认证失败"
        except jwt.InvalidTokenError:
            msg = "非法的token"
        if not payload:
            return Response({'code':1003,'error':msg})
        print(payload['user_id'],payload['username'])
        return Response({'data':"获取订单"})

class ProLoginView(APIView):
    """基于jwt用户登录"""
    authentication_classes = []
    def post(self,request,*args,**kwargs):
        user = request.data.get('username')
        pwd = request.data.get('password')
        user_object = models.UserInfo.objects.filter(username=user,password=pwd).first()
        if not user_object:
            return Response({'code':1000,'error':'用户名或密码错误'})
        token = create_token({'id':user_object.id,'name':user_object.username},1)
        return Response({'code':1001,'data':token})

class ProOrderView(APIView):
    authentication_classes = [JwtQueryParmsAuthentication,]
    def get(self, request, *args, **kwargs):
        print(request.user)
        return Response('订单列表')