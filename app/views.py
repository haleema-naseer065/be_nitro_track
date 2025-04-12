import datetime
import json
import bcrypt
import jwt as pyjwt
import cv2
# import numpy as np
# import os
# from django.http import JsonResponse, HttpResponse
# from django.core.files.storage import FileSystemStorage
# from matplotlib import pyplot as plt
# import io
# import base64
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

# -------------------------
# New Views with JWT Protection
# -------------------------

#@method_decorator(csrf_exempt, name='dispatch')
class ViewUsers(APIView):
    #@jwt_required
    def post(self, request):
        try:
            # Get user info from JWT
            user = User.objects(id=request.user_id).first()

            # Check if user is admin
            if user.role != 'admin':
                return Response({"error": "Access denied. Only admins can view users."}, status=status.HTTP_403_FORBIDDEN)

            users = User.objects(role='user').only("phoneNumber", "name", "role")
            users_list = [{
                "phoneNumber": u.phoneNumber,
                "name": u.name,
                "role": u.role
            } for u in users]

            return Response({"users": users_list}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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

#-----------------------------------------------------------------------------
# Image load, preprocessing, segmentation and nitrogen estimation logic below:
#-----------------------------------------------------------------------------

# def is_image_blurry(image_path, default_threshold=100):
#     image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
#     if image is None:
#         return None  # Signal invalid image
#     laplacian_var = cv2.Laplacian(image, cv2.CV_64F).var()
#     return laplacian_var < default_threshold


# def detect_leaves(image_path, min_contour_area=500, min_aspect_ratio=1.5, max_aspect_ratio=8.0, solidity_threshold=0.8):
#     image = cv2.imread(image_path)
#     hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
#     lower_green = np.array([25, 40, 40])
#     upper_green = np.array([85, 255, 255])
#     mask = cv2.inRange(hsv, lower_green, upper_green)

#     kernel = np.ones((3, 3), np.uint8)
#     mask = cv2.erode(mask, kernel, iterations=1)
#     mask = cv2.dilate(mask, kernel, iterations=2)

#     contours, _ = cv2.findContours(mask, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
#     for contour in contours:
#         area = cv2.contourArea(contour)
#         if area < min_contour_area:
#             continue
#         x, y, w, h = cv2.boundingRect(contour)
#         aspect_ratio = float(w) / h
#         if not (min_aspect_ratio <= aspect_ratio <= max_aspect_ratio):
#             continue
#         hull = cv2.convexHull(contour)
#         hull_area = cv2.contourArea(hull)
#         if hull_area == 0:
#             continue
#         solidity = float(area) / hull_area
#         if solidity < solidity_threshold:
#             continue
#         return True
#     return False

# def analyze_image(image_path):
#     is_blurry = is_image_blurry(image_path)
#     if is_blurry is None:
#         return "براہ کرم درست تصویر اپ لوڈ کریں۔"  # invalid image file
#     if is_blurry:
#         return "براہ کرم تصویر کو دوبارہ لیں یا صحیح تصویر منتخب کریں۔"
#     if not detect_leaves(image_path):
#         return "براہ کرم تصویر کو دوبارہ لیں یا صحیح تصویر منتخب کریں۔"
#     return "تصویر درست ہے۔ پتے موجود ہیں۔"


# def process_image(image):
#     hsv = cv2.cvtColor(image, cv2.COLOR_BGR2HSV)
#     lower_green = np.array([35, 40, 40])
#     upper_green = np.array([90, 255, 255])
#     mask = cv2.inRange(hsv, lower_green, upper_green)
#     kernel = np.ones((5, 5), np.uint8)
#     mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel)
#     mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel)
#     contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
#     contours = sorted(contours, key=cv2.contourArea, reverse=True)[:2]
#     if len(contours) < 2:
#         return mask, []
#     if contours[0][0][0][0] > contours[1][0][0][0]:
#         contours[0], contours[1] = contours[1], contours[0]
#     return mask, contours

# def mask_leaf(image, contour):
#     mask = np.zeros(image.shape[:2], dtype=np.uint8)
#     cv2.drawContours(mask, [contour], -1, 255, thickness=-1)
#     leaf_region = cv2.bitwise_and(image, image, mask=mask)
#     x, y, w, h = cv2.boundingRect(contour)
#     return leaf_region[y:y+h, x:x+w]

# def remove_black_background(image):
#     image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
#     black_mask = np.all(image_rgb < [30, 30, 30], axis=-1)
#     image_rgb[black_mask] = [0, 0, 0]
#     return image_rgb, ~black_mask

# def extract_y_channel(image_rgb, leaf_mask):
#     image_rgb_norm = image_rgb.astype(np.float32) / 255.0
#     image_xyz = cv2.cvtColor(image_rgb_norm, cv2.COLOR_RGB2XYZ)
#     y_channel = image_xyz[:, :, 1] * 255
#     y_channel[leaf_mask == 0] = 0
#     return y_channel

# def determine_nitrogen(spad_index, crop_id):
#     if crop_id == 0:
#         if spad_index > 95:
#             return {"message": "نائٹروجن کی ضرورت نہیں۔"}
#         elif 90 <= spad_index <= 95:
#             nit = 10.12
#         else:
#             nit = 20.25
#     elif crop_id == 1:
#         if spad_index > 95:
#             return {"message": "نائٹروجن کی ضرورت نہیں۔"}
#         elif 90 <= spad_index <= 95:
#             nit = 12.14
#         else:
#             nit = 23.08
#     else:
#         return {"error": "غلط فصل کی شناخت۔"}

#     return {
#         "nitrogen_required_kg_per_acre": round(nit, 2),
#         "urea_kg": round(nit * (100 / 46), 2),
#         "CAN_kg": round(nit * (100 / 26), 2),
#         "ammonium_sulphate_kg": round(nit * (100 / 21), 2)
#     }

# def convert_image_to_base64(image):
#     _, img_encoded = cv2.imencode('.png', image)
#     return base64.b64encode(img_encoded).decode('utf-8')

# @csrf_exempt
# def upload_and_process(request):
#     if request.method == 'POST' and request.FILES.get('image') and request.POST.get('crop_id') is not None:
#         try:
#             crop_id = int(request.POST['crop_id'])
#         except ValueError:
#             return JsonResponse({'error': 'Invalid crop_id. Should be 0 or 1.'}, status=400)

#         # Save uploaded image temporarily
#         image_file = request.FILES['image']
#         fs = FileSystemStorage()
#         filename = fs.save(image_file.name, image_file)
#         image_path = os.path.join(os.getcwd(), fs.url(filename)[1:])

#         # 📌 Step 1: Validate image for blurriness and leaf detection
#         result = analyze_image(image_path)
#         if result != "تصویر درست ہے۔ پتے موجود ہیں۔":
#             # Delete temporary file after use
#             fs.delete(filename)
#             return JsonResponse({'result': result})

#         # 📌 Step 2: Process image (already verified)
#         image = cv2.imread(image_path)
#         mask, contours = process_image(image)

#         # Require exactly 2 leaves, else reject
#         if len(contours) != 2:
#             fs.delete(filename)
#             return JsonResponse({'error': 'دو مکمل پتے نہیں ملے۔'}, status=400)

#         # 📌 Step 3: Segment leaves and process them
#         left_leaf = mask_leaf(image, contours[0])
#         right_leaf = mask_leaf(image, contours[1])

#         left_rgb, left_mask = remove_black_background(left_leaf)
#         right_rgb, right_mask = remove_black_background(right_leaf)

#         y_left = extract_y_channel(left_rgb, left_mask)
#         y_right = extract_y_channel(right_rgb, right_mask)

#         y_left_mean = float(np.mean(y_left[y_left > 0]))
#         y_right_mean = float(np.mean(y_right[y_right > 0]))

#         # 📌 Step 4: Calculate SPAD index
#         spad_full = float(3.1713 * y_left_mean - 226.13)
#         spad_test = float(3.1713 * y_right_mean - 226.13)
#         spad_index = float((spad_test / spad_full) * 100)

#         # 📌 Step 5: Determine nitrogen recommendation
#         fertilizer_info = determine_nitrogen(spad_index, crop_id)

#         # Delete temporary file after processing
#         fs.delete(filename)

#         # 📌 Step 6: Prepare JSON response
#         if "message" in fertilizer_info:
#             return JsonResponse({
#                 'spad_index': round(spad_index, 2),
#                 'message': fertilizer_info["message"],
#                 'test_leaf_segmented': convert_image_to_base64(right_leaf),
#             })

#         return JsonResponse({
#             'spad_index': round(spad_index, 2),
#             'nitrogen_required_kg_per_acre': fertilizer_info["nitrogen_required_kg_per_acre"],
#             'urea_kg': fertilizer_info["urea_kg"],
#             'CAN_kg': fertilizer_info["CAN_kg"],
#             'ammonium_sulphate_kg': fertilizer_info["ammonium_sulphate_kg"],
#             'test_leaf_segmented': convert_image_to_base64(right_leaf),
#         })

#     return JsonResponse({'error': 'Image and crop_id required.'}, status=400)
