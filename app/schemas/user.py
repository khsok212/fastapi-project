from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from datetime import datetime

# User 스키마
class UserSchema(BaseModel):
    user_id: str  # 회원 고유 ID (문자열 형식)
    name: str  # 이름
    email: EmailStr  # 이메일 (유효성 검사)
    phone: Optional[str] = None  # 전화번호 (선택적)
    address: Optional[str] = None  # 주소 (선택적)
    approval_status: str = Field(default='N', max_length=1)  # 승인 여부 ('Y' = 승인, 'N' = 미승인)
    role_id: Optional[int] = None  # null 허용 가능하도록 수정
    created_at: Optional[datetime] = None  # 가입일 (타임스탬프)
    role_ids: Optional[List[int]] = []  # 권한 ID 리스트
    
    class Config:
        orm_mode = True  # ORM 모드 활성화
        from_attributes = True  # from_orm을 사용할 수 있도록 설정

class UserCreate(UserSchema):
    password: str  # 비밀번호 (해싱 필요)
    # role_id: int  # 권한 고유 ID

class UserUpdate(UserSchema):
    password: Optional[str] = None  # 비밀번호 (선택적)

class User(UserSchema):
    created_at: str  # 가입일 (TIMESTAMP 형식)

class UsersRequest(BaseModel):
    user_ids: List[str]  # user_id 리스트

# Role 스키마
class RoleBase(BaseModel):
    role_id: int  # 권한 고유 ID
    role_name: str  # 권한 유형

class RoleCreate(RoleBase):
    pass

class Role(RoleBase):
    pass

# UserRole 스키마
class UserRoleBase(BaseModel):
    user_role_id: Optional[int]  # 회원 권한 ID (Optional로 변경)
    user_id: str  # 회원 ID (TEXT 타입)
    role_id: int  # 권한 ID

    class Config:
        orm_mode = True  # ORM 모드 활성화
        from_attributes = True  # from_orm을 사용할 수 있도록 설정

class UserRoleCreate(UserRoleBase):
    pass

class UserRoles(UserRoleBase):
    pass

class UserRoleList(BaseModel):
    role_id: int  # 권한 ID

    class Config:
        orm_mode = True  # ORM 모드 활성화
        from_attributes = True  # from_orm을 사용할 수 있도록 설정

# UserHistory 스키마
class UserHistoryBase(BaseModel):
    history_id: int  # 이력 고유 ID
    user_id: str  # 회원 ID (TEXT 타입)
    login_time: str  # 접속 일시
    login_ip: Optional[str] = None  # 접속한 IP 주소 (선택적)

class UserHistoryCreate(UserHistoryBase):
    pass

class UserHistory(UserHistoryBase):
    pass

# 전체 스키마 리스트
class UserResponse(User):
    roles: List[Role] = []  # 사용자의 역할 목록

class UserRoleResponse(UserRoles):
    user: User  # 사용자 정보
    role: Role  # 권한 정보

class LoginRequest(BaseModel):
    user_id: str
    password: str