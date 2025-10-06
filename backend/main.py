import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
from pydantic import BaseModel, EmailStr
from typing import List, Optional
import datetime
import jwt
from dotenv import load_dotenv

# --- NEW: Import Cashfree PG ---
from cashfree_pg.api_client import Cashfree
from cashfree_pg.api.orders_api import OrdersApi
from cashfree_pg.models.create_order_request import CreateOrderRequest
from cashfree_pg.models.order_customer_details import OrderCustomerDetails

# --- Load Environment Variables ---
load_dotenv()

# --- Configuration ---
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret-key")
OPENAI_PROJECT_ID = os.getenv("OPENAI_PROJECT_ID")
ALGORITHM = "HS256"

# --- NEW: Cashfree Configuration ---
CASHFREE_APP_ID = os.getenv("CASHFREE_APP_ID")
CASHFREE_SECRET_KEY = os.getenv("CASHFREE_SECRET_KEY")
# Use 'SANDBOX' for testing, 'PRODUCTION' for live payments
Cashfree.XClientId = CASHFREE_APP_ID
Cashfree.XClientSecret = CASHFREE_SECRET_KEY
Cashfree.XEnvironment = Cashfree.SANDBOX 

# --- Mock Database ---
fake_users_db = {}
fake_transcriptions_db = {}
transcription_id_counter = 1

# --- Pydantic Models (Data Schemas) ---
class User(BaseModel):
    email: EmailStr
    user_type: str
    transcription_count: int
    last_transcription_date: Optional[datetime.datetime] = None

class UserInDB(User):
    hashed_password: str

class TokenData(BaseModel):
    email: Optional[EmailStr] = None

class Transcription(BaseModel):
    id: int
    email: EmailStr
    original_text: str
    corrected_text: str
    audio_url: str
    created_at: datetime.datetime

# Initialize FastAPI app
app = FastAPI(
    title="SpeechParrot API",
    description="API for audio transcription, correction, and user management.",
    version="2.3.1" # Version bump for webhook fix
)

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Helper Functions & Security ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(authorization: Optional[str] = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None or email not in fake_users_db:
            raise HTTPException(status_code=401, detail="Invalid token")
        return fake_users_db[email]
    except (jwt.PyJWTError, IndexError):
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"status": "SpeechParrot API is running"}

# --- Authentication Endpoints ---
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    confirm_password: str

@app.post("/auth/signup")
async def signup(user: UserCreate):
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    if user.email in fake_users_db:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = user.password + "notreallyhashed"
    new_user = UserInDB(
        email=user.email,
        hashed_password=hashed_password,
        user_type='free',
        transcription_count=0
    )
    fake_users_db[user.email] = new_user.dict()
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

class UserLogin(BaseModel):
    email: EmailStr
    password: str

@app.post("/auth/login")
async def login(form_data: UserLogin):
    user = fake_users_db.get(form_data.email)
    if not user or (form_data.password + "notreallyhashed") != user['hashed_password']:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": form_data.email})
    return {"access_token": access_token, "token_type": "bearer"}

# --- User Endpoints ---
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user

# --- Admin Dashboard Endpoint ---
@app.get("/admin/dashboard")
async def get_admin_dashboard(secret: str):
    """
    A simple protected endpoint to view the in-memory database.
    Access it by going to /admin/dashboard?secret=YOUR_SECRET_KEY
    """
    # Load the admin secret from environment variables for security
    ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "default-admin-secret")

    if secret != ADMIN_SECRET_KEY:
        raise HTTPException(status_code=403, detail="Incorrect secret key")

    return {
        "users": fake_users_db,
        "transcriptions": fake_transcriptions_db
    }

# --- Payment Endpoints ---
@app.post("/payments/create-order")
async def create_payment_order(current_user: dict = Depends(get_current_user)):
    user_email = current_user['email']
    order_id = f"order_{int(datetime.datetime.now().timestamp())}_{user_email}"

    try:
        orders_api = OrdersApi(api_client=Cashfree.get_api_client())
        create_order_request = CreateOrderRequest(
            order_id=order_id,
            order_amount=299.00,
            order_currency="INR",
            customer_details=OrderCustomerDetails(
                customer_id=user_email,
                customer_email=user_email,
                customer_phone="9999999999"
            ),
            order_meta={"return_url": f"http://speechparrot.purelementlabs.com/?order_id={{order_id}}"}
        )
        api_response = orders_api.create_order(x_api_version="2022-09-01", create_order_request=create_order_request)
        return {"payment_session_id": api_response.payment_session_id}
    except Exception as e:
        print(f"Cashfree API Error: {e}")
        raise HTTPException(status_code=500, detail="Could not create payment order.")

# --- EDITED: Made webhook more robust for testing ---
@app.post("/payments/webhook")
async def payment_webhook(request: Request):
    # In a real app, you would verify the webhook signature from Cashfree
    try:
        data = await request.json()
        print("Received webhook:", data)
        
        if data.get("data", {}).get("order", {}).get("order_status") == "PAID":
            customer_email = data.get("data", {}).get("customer_details", {}).get("customer_email")
            if customer_email in fake_users_db:
                # Upgrade user to 'paid' and reset their count
                fake_users_db[customer_email]['user_type'] = 'paid'
                fake_users_db[customer_email]['transcription_count'] = 0
                print(f"Successfully upgraded user: {customer_email}")
        
        return {"status": "ok"}
    except Exception:
        # This handles the initial test webhook from Cashfree which may not have a valid body.
        # We simply acknowledge it with a success status code so it can be saved.
        print("Received a webhook test request or a request with no JSON body.")
        return {"status": "webhook_test_acknowledged"}


# --- Transcription Endpoints ---
@app.post("/transcriptions/")
async def process_audio(
    audio_file: UploadFile = File(...),
    authorization: Optional[str] = Header(None)
):
    global transcription_id_counter
    email = "guest"
    user_data = None

    if authorization and authorization.startswith("Bearer "):
        try:
            user_data = await get_current_user(authorization)
            email = user_data['email']
        except HTTPException:
            pass

    if user_data:
        if user_data['user_type'] == 'free' and user_data['transcription_count'] >= 10:
            raise HTTPException(status_code=403, detail="Free user limit reached.")
        if user_data['user_type'] == 'paid' and user_data['transcription_count'] >= 1000:
             raise HTTPException(status_code=403, detail="Monthly subscription limit reached.")

    audio_bytes = await audio_file.read()
    mock_audio_url = f"/audio/{email.split('@')[0]}_{transcription_id_counter}.webm"
    transcribed_text = ""
    corrected_text = ""

    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            whisper_url = "https://api.openai.com/v1/audio/transcriptions"
            headers = {'Authorization': f'Bearer {OPENAI_API_KEY}'}
            if OPENAI_PROJECT_ID:
                headers['OpenAI-Project'] = OPENAI_PROJECT_ID
            
            files = {'file': (audio_file.filename, audio_bytes, audio_file.content_type)}
            data = {'model': 'whisper-1'}
            
            whisper_response = await client.post(whisper_url, headers=headers, files=files, data=data)
            whisper_response.raise_for_status()
            transcribed_text = whisper_response.json()['text']

            if transcribed_text:
                gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
                prompt = f"Please correct the grammar and structure of the following text, but keep the original meaning. Do not add any preamble or explanation, just provide the corrected text:\n\n'{transcribed_text}'"
                payload = {"contents": [{"parts": [{"text": prompt}]}]}
                
                gemini_response = await client.post(gemini_url, json=payload)
                gemini_response.raise_for_status()
                corrected_text = gemini_response.json()['candidates'][0]['content']['parts'][0]['text'].strip()
        except httpx.HTTPStatusError as e:
            error_detail = e.response.json().get('error', {}).get('message', 'Unknown Error')
            raise HTTPException(status_code=e.response.status_code, detail=f"An external API error occurred: {error_detail}")
        except Exception as e:
            raise HTTPException(status_code=500, detail="An unexpected error occurred while processing the audio.")

    if user_data:
        new_transcription = Transcription(
            id=transcription_id_counter,
            email=email,
            original_text=transcribed_text,
            corrected_text=corrected_text,
            audio_url=mock_audio_url,
            created_at=datetime.datetime.utcnow()
        )
        fake_transcriptions_db[transcription_id_counter] = new_transcription.dict()
        transcription_id_counter += 1
        fake_users_db[email]['transcription_count'] += 1

    return {"original_transcription": transcribed_text, "corrected_text": corrected_text, "is_guest": (user_data is None)}

@app.get("/transcriptions/", response_model=List[Transcription])
async def get_transcription_history(current_user: dict = Depends(get_current_user)):
    user_transcriptions = [t for t in fake_transcriptions_db.values() if t['email'] == current_user['email']]
    return sorted(user_transcriptions, key=lambda x: x['created_at'], reverse=True)

