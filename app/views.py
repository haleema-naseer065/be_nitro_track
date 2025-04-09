
import datetime
import json
import bcrypt
import jwt as pyjwt
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils.timezone import now
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from mongoengine import DoesNotExist

from app.utils import jwt_required
from Nitro_Track import settings
from .models import User

SECRET_KEY = settings.SECRET_KEY_JWT

# -------------------------
# Existing Functions
# -------------------------

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
            if not pin.isdigit() or len(pin) != 4:
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
            # Debug print
            print("User saved:", user.to_json())
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


# @jwt_required
# def user_profile(request):
#     try:
#         user = User.objects(id=request.user_id).first()
#         if not user:
#             return JsonResponse({"error": "User not found"}, status=404)

#         return JsonResponse({
#             "id": str(user.id),
#             "name": user.name,
#             "phoneNumber": user.phoneNumber,
#             "role": user.role
#         }, status=200)

#     except Exception as e:
#         return JsonResponse({"error": str(e)}, status=500)

# -------------------------
# New Views with JWT Protection
# -------------------------

#@method_decorator(csrf_exempt, name='dispatch')
# class ViewUsers(APIView):
#     #@jwt_required
#     def post(self, request):
#         try:
#             # Get user info from JWT
#             user = User.objects(id=request.user_id).first()

#             # Check if user is admin
#             if user.role != 'admin':
#                 return Response({"error": "Access denied. Only admins can view users."}, status=status.HTTP_403_FORBIDDEN)

#             users = User.objects(role='user').only("phoneNumber", "name", "role")
#             users_list = [{
#                 "phoneNumber": u.phoneNumber,
#                 "name": u.name,
#                 "role": u.role
#             } for u in users]

#             return Response({"users": users_list}, status=status.HTTP_200_OK)

#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@jwt_required
def user_profile(request):
    try:
        user = User.objects(id=request.user_id).first()
        if not user:
            return JsonResponse({"error": "User not found"}, status=404)

        # Only allow admin to fetch all users
        if user.role != "admin":
            return JsonResponse({"error": "Access denied. Admins only."}, status=403)

        all_users = User.objects()
        user_data = []

        for u in all_users:
            user_data.append({
                "id": str(u.id),
                "name": u.name,
                "phoneNumber": u.phoneNumber,
                "role": u.role
            })

        return JsonResponse({"users": user_data}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


#@method_decorator(csrf_exempt, name='dispatch')
class DeleteUser(APIView):
    #@jwt_required
    def post(self, request):
        try:
            body = json.loads(request.body)
            target_phone = body.get("target_phone")

            if not target_phone:
                return Response({"error": "Target phone number is required"}, status=status.HTTP_400_BAD_REQUEST)

            # Get user info from JWT
            user = User.objects(id=request.user_id).first()

            if user.role != 'admin':
                return Response({"error": "Access denied. Only admins can delete users."}, status=status.HTTP_403_FORBIDDEN)

            result = User.objects(phoneNumber=target_phone).first()

            if result:
                result.delete()
                return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@csrf_exempt
@jwt_required
def edit_profile(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)

            new_name = data.get("name")
            new_phone_number = data.get("new_phone_number")

            user = User.objects(id=request.user_id).first()

            if not user:
                return JsonResponse({"error": "User not found"}, status=404)

            # Update fields dynamically
            update_data = {}
            if new_name:
                update_data["name"] = new_name

            if new_phone_number:
                # Check if new phone number already exists
                if User.objects(phoneNumber=new_phone_number).first():
                    return JsonResponse({"error": "Phone number already in use"}, status=400)
                update_data["phoneNumber"] = new_phone_number

            user.update(**update_data)

            return JsonResponse({"message": "Profile updated successfully"})

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)
