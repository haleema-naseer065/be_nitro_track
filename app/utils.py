# Decorator:modifies behaviour of another function without changing its behaviour

import jwt
from functools import wraps
from django.http import JsonResponse
from Nitro_Track import settings

SECRET_KEY = settings.SECRET_KEY_JWT

def jwt_required(view_func):
    
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return JsonResponse({"error": "Token required"}, status=401)

        try:
            token = auth_header.split(" ")[1] 
            payload = jwt.decode(token, SECRET_KEY, algorithms="HS256")

            request.user_id = payload["id"]
            request.user_role = payload["role"]

        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token has expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)

        return view_func(request, *args, **kwargs)

    return wrapper
