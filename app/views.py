import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from app.utils import jwt_required
from Nitro_Track import settings
from mongoengine import DoesNotExist
from django.utils.timezone import now
import bcrypt
import jwt as pyjwt

from .models import User
import json

SECRET_KEY = settings.SECRET_KEY_JWT

@csrf_exempt
def sign_up(request):
    if request.method == 'POST':
        try:
            body = json.loads(request.body)
           
            name = body.get('name', '').strip()
            phoneNumber = body.get('phoneNumber', '').strip()
            pin = body.get('pin', '').strip()
           
            if not name:
                return JsonResponse({'error': 'Name is required'}, status=400)
            if not phoneNumber:
                return JsonResponse({'error': 'Phone Number is required'}, status=400)
            if not pin: 
                return JsonResponse({'error': 'Pin is required'}, status=400)
            if not pin.isdigit() or len(pin)!= 4:
                 return JsonResponse({'error': 'Pin is invalid'}, status=400)
            
            if User.objects(phoneNumber=phoneNumber).first():
                return JsonResponse({'error': 'Phone number is already registered'}, status=400)

            hashed_pin = bcrypt.hashpw(pin.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            user = User(
                name=name,
                phoneNumber=phoneNumber,
                pin=hashed_pin,    
            )
            user.save()
            return JsonResponse({'message': 'User created successfully', 'id': str(user.id)})

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

def generate_jwt_token(user_id, role):
   
    payload = {
        "id": str(user_id),
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)  
    }

    return pyjwt.encode(payload, SECRET_KEY, algorithm="HS256")  

@csrf_exempt
def signin_user(request):
    
    if request.method == "POST":
        try:
            body = json.loads(request.body)

            phone_number = body.get("phoneNumber", "").strip()
            pin = body.get("pin", "").strip()

            if not phone_number:
                return JsonResponse({"error": "Phone Number is required"}, status=400)
            if not pin:
                return JsonResponse({"error": "PIN is required"}, status=400)

            user = User.objects(phoneNumber=phone_number).first()
            if not user:
                return JsonResponse({"error": "User not found"}, status=404)

            if not bcrypt.checkpw(pin.encode("utf-8"), user.pin.encode("utf-8")):
                return JsonResponse({"error": "Invalid PIN"}, status=401)

            token = generate_jwt_token(user.id, user.role)

            return JsonResponse({"token": token}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        except Exception as e:
            return JsonResponse({"error": f"Internal Server Error: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@jwt_required
def user_profile(request):
   
    try:
        user = User.objects(id=request.user_id).first()
        if not user:
            return JsonResponse({"error": "User not found"}, status=404)

        return JsonResponse({
            "id": str(user.id),
            "name": user.name,
            "phoneNumber": user.phoneNumber,
            "role": user.role
        }, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


