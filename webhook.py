from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import PlainTextResponse, HTMLResponse
import hmac
import hashlib
import json
import os

app = FastAPI()

# Get from environment variables (we'll set these on Render)
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "my_secret_verify_token_12345")
APP_SECRET = os.getenv("APP_SECRET", "your_app_secret_here")

# Store messages in memory (or use a database later)
messages_log = []

@app.get("/")
async def home():
    return {"status": "WhatsApp Webhook Active", "messages_received": len(messages_log)}

@app.get("/privacy", response_class=HTMLResponse)
async def privacy_policy():
    """Privacy Policy Page"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Privacy Policy</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                line-height: 1.6;
            }
            h1 { color: #333; }
            h2 { color: #666; margin-top: 30px; }
            p { margin: 15px 0; }
        </style>
    </head>
    <body>
        <h1>Privacy Policy</h1>
        <p><strong>Last updated:</strong> January 2026</p>
        
        <h2>Information We Collect</h2>
        <p>We collect and store WhatsApp messages sent to our business account for the purpose of 
        providing customer support and business communication services.</p>
        
        <h2>How We Use Your Information</h2>
        <p>The information collected is used solely for:</p>
        <ul>
            <li>Responding to customer inquiries</li>
            <li>Providing requested services</li>
            <li>Improving our customer service</li>
        </ul>
        
        <h2>Data Security</h2>
        <p>We implement appropriate technical and organizational measures to protect your personal 
        data against unauthorized access, alteration, disclosure, or destruction.</p>
        
        <h2>Data Sharing</h2>
        <p>We do not sell, trade, or share your personal information with third parties except as 
        required by law or with your explicit consent.</p>
        
        <h2>Your Rights</h2>
        <p>You have the right to:</p>
        <ul>
            <li>Access your personal data</li>
            <li>Request deletion of your data</li>
            <li>Object to processing of your data</li>
        </ul>
        
        <h2>Contact Us</h2>
        <p>If you have questions about this Privacy Policy, please contact us at:<br>
        Email: privacy@yourcompany.com</p>
        
        <h2>Changes to This Policy</h2>
        <p>We may update this Privacy Policy from time to time. We will notify you of any changes 
        by posting the new Privacy Policy on this page.</p>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/webhook")
async def verify_webhook(request: Request):
    """Webhook verification"""
    mode = request.query_params.get('hub.mode')
    token = request.query_params.get('hub.verify_token')
    challenge = request.query_params.get('hub.challenge')
    
    print(f"Verification attempt - Mode: {mode}, Token: {token}")
    
    if mode == 'subscribe' and token == VERIFY_TOKEN:
        print("✓ Webhook verified successfully!")
        return PlainTextResponse(challenge)
    else:
        print("✗ Verification failed")
        raise HTTPException(status_code=403, detail="Forbidden")

@app.post("/webhook")
async def receive_message(request: Request):
    """Receive incoming messages"""
    body = await request.json()
    
    print("\n" + "="*70)
    print("📨 WEBHOOK RECEIVED")
    print("="*70)
    print(json.dumps(body, indent=2))
    
    # Verify signature
    signature = request.headers.get('x-hub-signature-256', '')
    body_bytes = await request.body()
    
    if not verify_signature(body_bytes, signature):
        print("❌ Invalid signature!")
        raise HTTPException(status_code=403, detail="Invalid signature")
    
    # Process message
    if body.get('object') == 'whatsapp_business_account':
        for entry in body.get('entry', []):
            for change in entry.get('changes', []):
                value = change.get('value', {})
                
                if 'messages' in value:
                    for message in value['messages']:
                        from_number = message['from']
                        message_type = message['type']
                        message_id = message['id']
                        
                        print(f"\n✅ NEW MESSAGE RECEIVED!")
                        print(f"From: {from_number}")
                        print(f"Type: {message_type}")
                        print(f"ID: {message_id}")
                        
                        if message_type == 'text':
                            text = message['text']['body']
                            print(f"Text: {text}")
                            
                            # Store message
                            message_data = {
                                'from': from_number,
                                'text': text,
                                'id': message_id,
                                'timestamp': message.get('timestamp')
                            }
                            messages_log.append(message_data)
                            print(f"Total messages stored: {len(messages_log)}")
                        
                        print("="*70 + "\n")
    
    return {"status": "ok"}

@app.get("/messages")
async def get_messages():
    """View all received messages"""
    return {
        "total": len(messages_log),
        "messages": messages_log
    }

def verify_signature(payload: bytes, signature: str) -> bool:
    """Verify webhook signature"""
    expected_signature = 'sha256=' + hmac.new(
        APP_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, signature)

if __name__ == '__main__':
    import uvicorn
    port = int(os.getenv("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
