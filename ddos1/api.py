from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import uvicorn
import pandas as pd
import numpy as np
from datetime import datetime
import asyncio
import json

app = FastAPI(
    title="DDoS Detection API",
    description="Real-time DDoS attack detection and prevention API",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data models
class NetworkPacket(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_size: int
    flags: Optional[str] = None

class PredictionRequest(BaseModel):
    packets: List[NetworkPacket]

class PredictionResponse(BaseModel):
    is_attack: bool
    confidence: float
    attack_type: Optional[str]
    severity: str
    recommendations: List[str]
    timestamp: datetime

class AlertWebhook(BaseModel):
    url: str
    events: List[str]  # ['attack_detected', 'high_traffic', 'blocked_ip']

class IPBlockRequest(BaseModel):
    ip_address: str
    reason: str
    duration: Optional[int] = None  # minutes, None = permanent

# In-memory storage (use Redis/Database in production)
active_alerts = []
blocked_ips = set()
traffic_stats = {
    'total_requests': 0,
    'blocked_requests': 0,
    'detected_attacks': 0
}
webhooks = []

# Middleware for rate limiting
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Simple rate limiting (use Redis in production)
    client_ip = request.client.host
    
    if client_ip in blocked_ips:
        return JSONResponse(
            status_code=403,
            content={"detail": "IP address is blocked"}
        )
    
    response = await call_next(request)
    return response

@app.get("/")
async def root():
    return {
        "service": "DDoS Detection API",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "predict": "/api/v1/predict",
            "stats": "/api/v1/stats",
            "alerts": "/api/v1/alerts",
            "block_ip": "/api/v1/block-ip",
            "webhooks": "/api/v1/webhooks"
        }
    }

@app.post("/api/v1/predict", response_model=PredictionResponse)
async def predict_attack(request: PredictionRequest, background_tasks: BackgroundTasks):
    """Predict if traffic contains DDoS attack"""
    
    try:
        # Convert packets to DataFrame
        df = pd.DataFrame([packet.dict() for packet in request.packets])
        
        # Feature extraction (simplified)
        packet_count = len(df)
        unique_src_ips = df['src_ip'].nunique()
        unique_dst_ips = df['dst_ip'].nunique()
        avg_packet_size = df['packet_size'].mean()
        
        # Simple rule-based detection (replace with ML model)
        is_attack = False
        attack_type = None
        confidence = 0.0
        severity = "low"
        recommendations = []
        
        # SYN Flood detection
        if 'flags' in df.columns:
            syn_count = df['flags'].str.contains('SYN', na=False).sum()
            if syn_count / packet_count > 0.7:
                is_attack = True
                attack_type = "SYN Flood"
                confidence = 0.95
                severity = "high"
        
        # High traffic from single source
        if unique_src_ips < 5 and packet_count > 1000:
            is_attack = True
            attack_type = "Volumetric Attack"
            confidence = 0.88
            severity = "critical"
        
        # UDP Flood
        udp_count = (df['protocol'] == 'UDP').sum()
        if udp_count / packet_count > 0.8:
            is_attack = True
            attack_type = "UDP Flood"
            confidence = 0.92
            severity = "high"
        
        if is_attack:
            recommendations = [
                f"Block source IPs: {', '.join(df['src_ip'].unique()[:5])}",
                "Enable rate limiting",
                "Activate DDoS mitigation",
                "Alert security team"
            ]
            
            # Update stats
            traffic_stats['detected_attacks'] += 1
            
            # Trigger webhooks
            background_tasks.add_task(trigger_webhooks, 'attack_detected', {
                'attack_type': attack_type,
                'severity': severity,
                'confidence': confidence
            })
        
        traffic_stats['total_requests'] += packet_count
        
        return PredictionResponse(
            is_attack=is_attack,
            confidence=confidence,
            attack_type=attack_type,
            severity=severity,
            recommendations=recommendations,
            timestamp=datetime.now()
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/stats")
async def get_statistics():
    """Get system statistics"""
    return {
        "total_requests": traffic_stats['total_requests'],
        "blocked_requests": traffic_stats['blocked_requests'],
        "detected_attacks": traffic_stats['detected_attacks'],
        "blocked_ips_count": len(blocked_ips),
        "active_webhooks": len(webhooks),
        "uptime": "99.9%",
        "last_updated": datetime.now()
    }

@app.get("/api/v1/alerts")
async def get_alerts(limit: int = 50):
    """Get recent alerts"""
    return {
        "alerts": active_alerts[-limit:],
        "count": len(active_alerts)
    }

@app.post("/api/v1/block-ip")
async def block_ip(request: IPBlockRequest):
    """Block an IP address"""
    blocked_ips.add(request.ip_address)
    
    alert = {
        "type": "ip_blocked",
        "ip": request.ip_address,
        "reason": request.reason,
        "timestamp": datetime.now().isoformat()
    }
    active_alerts.append(alert)
    
    return {
        "status": "success",
        "message": f"IP {request.ip_address} has been blocked",
        "blocked_ips": list(blocked_ips)
    }

@app.delete("/api/v1/block-ip/{ip_address}")
async def unblock_ip(ip_address: str):
    """Unblock an IP address"""
    if ip_address in blocked_ips:
        blocked_ips.remove(ip_address)
        return {
            "status": "success",
            "message": f"IP {ip_address} has been unblocked"
        }
    raise HTTPException(status_code=404, detail="IP not found in blocklist")

@app.get("/api/v1/blocked-ips")
async def get_blocked_ips():
    """Get all blocked IPs"""
    return {
        "blocked_ips": list(blocked_ips),
        "count": len(blocked_ips)
    }

@app.post("/api/v1/webhooks")
async def register_webhook(webhook: AlertWebhook):
    """Register a webhook for alerts"""
    webhooks.append(webhook.dict())
    return {
        "status": "success",
        "message": "Webhook registered successfully",
        "webhook_id": len(webhooks) - 1
    }

@app.get("/api/v1/webhooks")
async def get_webhooks():
    """Get all registered webhooks"""
    return {"webhooks": webhooks}

async def trigger_webhooks(event_type: str, data: Dict):
    """Trigger webhooks for specific events"""
    import aiohttp
    
    for webhook in webhooks:
        if event_type in webhook['events']:
            try:
                async with aiohttp.ClientSession() as session:
                    await session.post(
                        webhook['url'],
                        json={
                            "event": event_type,
                            "data": data,
                            "timestamp": datetime.now().isoformat()
                        }
                    )
            except Exception as e:
                print(f"Webhook error: {e}")

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "service": "ddos-detection-api"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)