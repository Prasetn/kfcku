import requests
import json
import random
import string
import time
from datetime import datetime
from faker import Faker
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import os

class KFCRegister:
    def __init__(self):
        self.session = requests.Session()
        self.base_url = "https://api-core.kfcku.co.id"
        self.device_id = '6a8340b6dc2aa4df'  # Use fixed device ID
        self.notif_token = "c21dKMo9SIaG9N7Sgt47ez:APA91bE32gvZ6tIi4qzXxwekE2TvL7PLxH_8-_xmmQA6ukHm0pAf9h3Ft_kO49eHDCbtVYk5tbqfiG95GTOj82g8VYabn6GC-RntuUikYgFqV8v4vruqEFw"
        self.headers = {
            "user-agent": "KFCKU/4.1.0 (Android 15; Redmi Note 8; ginkgo; arm64-v8a)",
            "sec-ch-ua-mobile": "?1",
            "accept-encoding": "gzip",
            "channel": "mobile",
            "device-id": self.device_id,
            "sec-ch-ua-platform-version": "15",
            "content-type": "application/json",
            "notif-token": self.notif_token,
            "sec-ch-ua-model": "Redmi Note 8",
            "sec-ch-ua-arch": "arm64-v8a",
            "language": "en",
            "accept-language": "en",
            "sec-ch-ua-full-version": "4.1.0",
            "sec-ch-ua-platform": "Android",
            "sec-ch-ua": "\"KFCKU\"; v=\"4.1.0\""
        }
        self.token = None
        self.phone_number = None
        self.email = None
        self.faker = Faker('id_ID')
        self.encryption_key = b'ThisIsASecretKey'  # 16 bytes
        self.iv = b'ThisIsAnInitVect'  # 16 bytes
        self.signature_key = "kfcku2024"  # Signature key
        self.encrypted_data = None  # Store encrypted data for OTP verification

    def encrypt_data(self, data):
        try:
            # Convert data to JSON string with minimal formatting
            json_data = json.dumps(data, separators=(',', ':'))
            print(f"\nOriginal JSON: {json_data}")
            
            # Create AES cipher in CBC mode with zero IV
            iv = b'\x00' * 16  # Zero IV
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            
            # Pad the data to be a multiple of 16 bytes using PKCS7
            padded_data = pad(json_data.encode('utf-8'), AES.block_size)
            
            # Encrypt the data
            encrypted_data = cipher.encrypt(padded_data)
            
            # Base64 encode the result
            encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
            
            # Verify encryption by decrypting
            decrypted = self.decrypt_data(encoded_data)
            print(f"Decrypted back: {decrypted}")
            
            if decrypted == json_data:
                print("Encryption verification successful!")
            else:
                print("WARNING: Encryption verification failed!")
                print(f"Original: {json_data}")
                print(f"Decrypted: {decrypted}")
            
            return encoded_data
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            return None

    def decrypt_data(self, encrypted_data):
        try:
            # Decode base64
            decoded_data = base64.b64decode(encrypted_data)
            
            # Create AES cipher in CBC mode with zero IV
            iv = b'\x00' * 16  # Zero IV
            cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
            
            # Decrypt the data
            decrypted_data = cipher.decrypt(decoded_data)
            
            # Unpad the data
            from Crypto.Util.Padding import unpad
            unpadded_data = unpad(decrypted_data, AES.block_size)
            
            # Convert back to string
            return unpadded_data.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            return None

    def generate_random_info(self):
        # Generate realistic name using Faker
        first_name = self.faker.first_name()
        last_name = self.faker.last_name()
        
        # Generate email based on name
        username = f"{first_name.lower()}.{last_name.lower()}"
        email = f"{username}@mailcuk.com"
        
        return {
            "email": email,
            "password": "123Qwerty@",  # Fixed password
            "first_name": first_name,
            "last_name": last_name
        }

    def validate_user(self, phone, email):
        try:
            # Format phone number without leading 0
            formatted_phone = phone.lstrip('0')
            
            # Prepare request data
            request_data = {
                "phone": formatted_phone,
                "email": email
            }
            
            # Make the request
            response = self.session.post(
                f"{self.base_url}/v1/user/validate-user",
                headers=self.headers,
                json=request_data
            )
            
            if response.status_code == 200:
                print("User validation successful!")
                return True
            else:
                print(f"User validation failed. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False
        except Exception as e:
            print(f"Error validating user: {str(e)}")
            return False

    def get_encrypted_data(self, phone, email, fullname):
        try:
            # Format phone number with country code
            formatted_phone = f"62{phone.lstrip('0')}"
            
            # Prepare request data
            request_data = {
                "phone": formatted_phone,
                "email": email,
                "fullname": fullname,
                "referral_code": None
            }
            
            # Make the request
            response = self.session.post(
                f"{self.base_url}/v1/user/encrypt-data",
                headers=self.headers,
                json=request_data
            )
            
            if response.status_code == 200:
                response_data = response.json()
                encrypted_data = response_data["response_output"]["detail"]["encrypted_data"]
                return encrypted_data
            else:
                print(f"Failed to get encrypted data. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return None
        except Exception as e:
            print(f"Error getting encrypted data: {str(e)}")
            return None

    def request_otp(self, phone_number):
        try:
            # Generate random user info
            user_info = self.generate_random_info()
            self.email = user_info["email"]
            fullname = f"{user_info['first_name']} {user_info['last_name']}"
            
            # Get encrypted data from server
            encrypted_data = self.get_encrypted_data(phone_number, self.email, fullname)
            if not encrypted_data:
                return False
            
            # Store encrypted data for verification
            self.encrypted_data = encrypted_data
            
            # Make the request with encrypted data
            payload = {
                "encrypted_data": encrypted_data,
                "otp_method": "sms",
                "purpose": "register"
            }
            
            response = self.session.post(
                f"{self.base_url}/v1/common/otp/request",
                headers=self.headers,
                json=payload
            )
            
            if response.status_code == 200:
                print(f"OTP request sent to {phone_number}")
                return True
            else:
                print(f"Failed to request OTP. Status code: {response.status_code}")
                return False
        except Exception as e:
            print(f"Error requesting OTP: {str(e)}")
            return False

    def verify_otp(self, phone_number, otp):
        try:
            # Use the same encrypted data from OTP request
            if not hasattr(self, 'encrypted_data'):
                print("No encrypted data found. Please request OTP first.")
                return False
            
            # Make the request with encrypted data
            payload = {
                "encrypted_data": self.encrypted_data,
                "code": otp,
                "purpose": "register"
            }
            
            response = self.session.post(
                f"{self.base_url}/v1/common/otp/validate",
                headers=self.headers,
                json=payload
            )
            
            if response.status_code == 200:
                print("OTP verification successful!")
                return True
            else:
                response_data = response.json()
                if "response_output" in response_data and "errors" in response_data["response_output"]:
                    for error in response_data["response_output"]["errors"]:
                        if error["field"] == "retry_count_left":
                            print(f"\nInvalid OTP. You have {error['message']} retries left.")
                            if int(error["message"]) > 0:
                                retry = input("Would you like to try again? (y/n): ")
                                if retry.lower() == 'y':
                                    new_otp = input("Enter the OTP again: ")
                                    return self.verify_otp(phone_number, new_otp)
                print(f"OTP verification failed. Status code: {response.status_code}")
                return False
        except Exception as e:
            print(f"Error verifying OTP: {str(e)}")
            return False

    def get_user_profile(self):
        try:
            if not self.token:
                print("No authentication token available. Please register first.")
                return False

            response = self.session.get(
                f"{self.base_url}/v1/user/me",
                headers=self.headers
            )

            if response.status_code == 200:
                profile_data = response.json()
                print("\nUser Profile:")
                print("-" * 50)
                print(f"Name: {profile_data.get('first_name', 'N/A')} {profile_data.get('last_name', 'N/A')}")
                print(f"Email: {profile_data.get('email', 'N/A')}")
                print(f"Phone: {profile_data.get('phone_number', 'N/A')}")
                print(f"Birth Date: {profile_data.get('birth_date', 'N/A')}")
                print(f"Gender: {profile_data.get('gender', 'N/A')}")
                print("-" * 50)
                return True
            else:
                print(f"Failed to get user profile. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False

        except Exception as e:
            print(f"An error occurred while getting user profile: {str(e)}")
            return False

    def set_pin(self, phone_number, pin):
        try:
            # Use the same encrypted data from OTP request
            if not hasattr(self, 'encrypted_data'):
                print("No encrypted data found. Please request OTP first.")
                return False
            
            # Make the request with encrypted data
            payload = {
                "pin_number": pin,
                "encrypted_data": self.encrypted_data
            }
            
            response = self.session.post(
                f"{self.base_url}/v1/user/register",
                headers=self.headers,
                json=payload
            )
            
            if response.status_code in [200, 201]:  # Accept both 200 and 201 as success
                print("PIN setup successful!")
                # Extract token from response
                try:
                    response_data = response.json()
                    if "response_output" in response_data and "detail" in response_data["response_output"]:
                        token = response_data["response_output"]["detail"].get("token")
                        if token:
                            self.token = token
                            self.headers['Authorization'] = f'Bearer {self.token}'
                except Exception as e:
                    print(f"Error extracting token: {str(e)}")
                return True
            else:
                print(f"PIN setup failed. Status code: {response.status_code}")
                return False
        except Exception as e:
            print(f"Error setting PIN: {str(e)}")
            return False

    def format_phone_number(self, phone):
        # Remove any non-digit characters
        phone = ''.join(filter(str.isdigit, phone))
        
        # If number starts with 0, remove it
        if phone.startswith('0'):
            phone = phone[1:]
            
        # If number starts with 62, remove it
        if phone.startswith('62'):
            phone = phone[2:]
            
        # If number doesn't start with 8, add it
        if not phone.startswith('8'):
            phone = '8' + phone
            
        return phone

    def register(self):
        try:
            print("\n" + "="*50)
            print("🍗 KFC Registration Bot".center(50))
            print("="*50)
            
            # Step 1: Get phone number from user
            input_phone = input("\n📱 Enter your phone number : ")
            self.phone_number = self.format_phone_number(input_phone)
            
            # Generate random user info using Faker
            user_info = self.generate_random_info()
            self.email = user_info["email"]
            first_name = user_info["first_name"]
            last_name = user_info["last_name"]
            password = user_info["password"]
            
            print("\n" + "-"*50)
            print("👤 Account Information".center(50))
            print("-"*50)
            print(f"📱 Phone    : {self.phone_number}")
            print(f"📧 Email    : {self.email}")
            print(f"🔑 Password : {password}")
            print(f"🔢 PIN      : 112233")
            print("-"*50)
            
            # Validate user first
            print("\n🔍 Validating user...")
            if not self.validate_user(self.phone_number, self.email):
                print("❌ User validation failed")
                return False
            
            # Request OTP
            print("\n📲 Requesting OTP...")
            if not self.request_otp(self.phone_number):
                return False

            # Get OTP from user
            otp = input("\n🔐 Enter the OTP received: ")
            
            # Verify OTP
            print("\n✅ Verifying OTP...")
            if not self.verify_otp(self.phone_number, otp):
                return False

            # Set PIN with default value
            print("\n🔒 Setting up PIN...")
            pin = "112233"  # Fixed PIN
            if not self.set_pin(self.phone_number, pin):
                return False
            
            # Registration is complete after PIN setup
            print("\n" + "="*50)
            print("🎉 Registration Successful!".center(50))
            print("="*50)
            
            return True

        except Exception as e:
            print(f"\n❌ An error occurred: {str(e)}")
            return False

    def save_account_info(self, phone, password, pin, voucher_expiry):
        try:
            # Format: phone|password|pin|voucher_expiry
            account_info = f"{phone}|{password}|{pin}|{voucher_expiry}\n"
            
            # Append to akun.txt
            with open("akun.txt", "a", encoding="utf-8") as f:
                f.write(account_info)
            
            print("\n" + "="*50)
            print("💾 Account information saved to akun.txt".center(50))
            print("="*50)
            return True
        except Exception as e:
            print(f"\n❌ Error saving account info: {str(e)}")
            return False

    def check_vouchers(self):
        try:
            if not self.token:
                print("\n❌ No authentication token available. Please register first.")
                return False

            # Prepare payload for voucher check
            payload = {
                "cart_id": None,
                "order_type": None,
                "delivery_method": None,
                "payment_method": None,
                "card_number": None,
                "selected_coupon_codes": [],
                "selected_voucher_codes": []
            }

            # Get available vouchers using POST request
            response = self.session.post(
                f"{self.base_url}/v1/voucher/me",
                headers=self.headers,
                json=payload
            )

            if response.status_code == 200:
                response_data = response.json()
                if "response_output" in response_data and "detail" in response_data["response_output"]:
                    vouchers = response_data["response_output"]["detail"].get("vouchers", [])
                    print("\n" + "="*50)
                    print("🎟️ Available Vouchers".center(50))
                    print("="*50)
                    
                    if not vouchers:
                        print("❌ No vouchers available at the moment.")
                        return True

                    voucher_expiry = None
                    for voucher in vouchers:
                        print("\n" + "-"*50)
                        print(f"🎁 {voucher.get('title', 'N/A')}")
                        print(f"🔑 Code: {voucher.get('code', 'N/A')}")
                        print(f"⏰ Exp: {voucher.get('expired_at', 'N/A')}")
                        print("-"*50)
                        # Get expiry date from first voucher (they all expire at the same time)
                        if not voucher_expiry:
                            voucher_expiry = voucher.get('expired_at', 'N/A')
                    
                    # Save account info after getting voucher expiry
                    self.save_account_info(
                        self.phone_number,
                        "123Qwerty@",
                        "112233",
                        voucher_expiry
                    )
                    return True
                else:
                    print("\n❌ Invalid response format")
                    return False
            else:
                print(f"\n❌ Failed to get vouchers. Status code: {response.status_code}")
                print(f"Response: {response.text}")
                return False

        except Exception as e:
            print(f"\n❌ An error occurred while checking vouchers: {str(e)}")
            return False

if __name__ == "__main__":
    kfc = KFCRegister()
    if kfc.register():
        print("\n🔍 Checking available vouchers...")
        kfc.check_vouchers()
