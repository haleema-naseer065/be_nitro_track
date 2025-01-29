import jwt
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

SECRET_KEY = settings.SECRET_KEY_JWT

class JWTAuthenticationMiddleware(MiddlewareMixin):
    
    def process_request(self, request):
        
        auth_header = request.headers.get("Authorization")
        
        if not auth_header or not auth_header.startswith("Bearer "):
           
            return None 

        token = auth_header.split(" ")[1]  

        try:
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"]) 
            request.user = decoded_token  
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)

        return None  
