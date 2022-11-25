from pydantic import BaseModel


class Cloudtrail(BaseModel):
    """Basemodel for cloudtrail results"""
    eventName: str
    eventType: str
    count: int


class WindowsEvent(BaseModel):
    """Basemodel for Windows (Audit) events"""
    signature_id: int
    category: str
    count: int
