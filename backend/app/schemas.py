from pydantic import BaseModel, Field
from typing import Optional, List

class CreateBaselineRequest(BaseModel):
    name: str = Field(..., description="Human-readable baseline label")
    directory_path: str = Field(..., description="Target directory path to snapshot")
    whitelist_extensions: Optional[List[str]] = Field(default=None, description="Allowed file extensions")

class ScanDirectoryRequest(BaseModel):
    baseline_id: str = Field(..., description="ID of baseline to verify against")
    files_snapshot: Optional[List[dict]] = Field(default=None, description="Simulated file list for virtual environments")

class AcknowledgeAlertRequest(BaseModel):
    alert_id: str
