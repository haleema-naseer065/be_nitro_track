import jwt
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

SECRET_KEY = settings.SECRET_KEY_JWT

class JWTAuthenticationMiddleware(MiddlewareMixin):
    
    def process_request(self, request):
        
        auth_header = request.headers.get("Authorization")
        #print("Authorization Header:", auth_header)  # Debugging

        if not auth_header or not auth_header.startswith("Bearer "):
            #print("No Authorization header or Bearer token")  # Debugging
            return None 

        token = auth_header.split(" ")[1]  
        #print("Extracted token:", token)  # Debugging

        try:
            decoded_token = jwt.decode(token, SECRET_KEY, algorithms=["HS256"]) 
            #print("Decoded token:", decoded_token)  # Debugging

            # Set these fields explicitly
            request.user_id = decoded_token.get('id')
            request.user_role = decoded_token.get('role')
            #request.user = decoded_token  
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)

        return None  
