from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.database.models import User, UserRole
from app.schemas.user import UserSchema, UserCreate, UserUpdate, LoginRequest, UserRoleList, UsersRequest  # Pydantic 스키마 가져오기
from app.utils.utils import verify_password  # 비밀번호 검증을 위한 유틸리티
from app.utils.utils import hash_password  # 비밀번호 해싱을 위한 유틸리티
from app.jwt import create_access_token, decode_access_token  # JWT 토큰 생성 함수 임포트
from datetime import timedelta
from fastapi.security import OAuth2PasswordBearer  # OAuth2 패스워드 베어러 가져오기
from jose import JWTError
from sqlalchemy import func

import logging
import re

router = APIRouter()
logger = logging.getLogger(__name__)  # 로거 생성
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")  # OAuth2 스킴 생성

# JWT 검증 함수
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        user_id: str = payload.get("sub")  # 'sub' 필L드에서 사용자 ID 가져오기
        if user_id is None:
            raise credentials_exception
    except (JWTError, Exception):
        raise credentials_exception

    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# 기본 루트 경로 추가
@router.get("/")
def root():
    return {"message": "Welcome to the FastAPI SQLite User API!"}

# 로그인 API
@router.post("/login/")
async def login(request: LoginRequest, db: Session = Depends(get_db)):

    user = db.query(User).filter(User.user_id == request.user_id).first()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 비밀번호 검증
    if not verify_password(request.password, user.password):  # 비밀번호 해시 검증
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # 로그인 성공 시 JWT 토큰 생성
    access_token_expires = timedelta(minutes=30)  # 토큰 만료 시간 설정
    access_token = create_access_token(data={"sub": user.user_id}, expires_delta=access_token_expires)

    # 권한 및 승인 여부 조회
    roles = (
        db.query(User, UserRole)
        .join(UserRole, User.user_id == UserRole.user_id)
        .filter(User.user_id == user.user_id)
        .all()
        )

    logger.info(f"roles: {roles}")  # f-string 사용

    # roles 리스트를 UserRoles 모델로 변환
    roles_data = []
    for user_obj, role_obj in roles:
        roles_data.append(UserRoleList(role_id=role_obj.role_id))

    return {
        "message": "로그인 성공",
        "user": UserSchema.from_orm(user),
        "roles": roles_data,  # 여기서 roles_data를 반환
        "access_token": access_token,
        "token_type": "bearer"  # 토큰 유형 (보통 "bearer" 사용)
    }

# 모든 사용자 조회 API
# @router.get("/api/users/", response_model=list[UserSchema])
# def read_all_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
#     users = (
#         db.query(User).all()
#     )
#     return users

@router.get("/api/users/", response_model=list[UserSchema])
def read_all_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    user_id: str = Query(None),
    name: str = Query(None),
    email: str = Query(None),
    phone: str = Query(None),
    approval_status: str = Query(None),
    role_ids: str = Query(None)
):
    query = db.query(User).outerjoin(UserRole).group_by(User.user_id).add_columns(
        User.user_id,
        User.name,
        User.email,
        User.phone,
        User.address,
        User.approval_status,
        User.created_at,
        func.group_concat(UserRole.role_id).label('role_ids')
    )

    # 필터 적용
    if user_id:
        query = query.filter(User.user_id.like(f"%{user_id}%"))
    if name:
        query = query.filter(User.name.like(f"%{name}%"))
    if email:
        query = query.filter(User.email.like(f"%{email}%"))
    if phone:
        query = query.filter(User.phone.like(f"%{phone}%"))
    if approval_status:
        query = query.filter(User.approval_status == approval_status)
    if role_ids:
        role_id_list = role_ids.split(',')  # role_ids를 리스트로 변환
        query = query.filter(UserRole.role_id.in_(role_id_list))  # 역할 필터링
    users = query.all()

    # 반환할 데이터 형식에 맞게 변환
    user_list = []
    for user in users:
        user_data = UserSchema(
            user_id=user.user_id,
            name=user.name,
            email=user.email,
            phone=user.phone,
            address=user.address,
            created_at=user.created_at,
            approval_status=user.approval_status,
            role_ids=[int(role_id) for role_id in user.role_ids.split(',')] if user.role_ids else []
        )
        user_list.append(user_data)

    return user_list


# 특정 사용자 조회 API
@router.get("/users/{user_id}", response_model=UserSchema)
def read_user(user_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# 특정 사용자 조회 직접 쿼리 실행 API(sql)
@router.get("/users/details/{user_id}")
def get_user_details(user_id: str, db: Session = Depends(get_db)):
    sql = text("""
        SELECT users.user_id, users.name, profiles.bio 
        FROM users 
        INNER JOIN profiles ON users.user_id = profiles.user_id
        WHERE id = :id
    """)
    result = db.execute(sql, {"id": user_id})
    users = result.fetchall()
    return users

# ID 중복 확인 API
@router.get("/api/users/check/{user_id}")
def check_user_id(user_id: str, db: Session = Depends(get_db)):
    # 사용자 존재 여부 확인
    existing_user = db.query(User).filter(User.user_id == user_id).first()
    if existing_user:
        return {"available": False}  # ID가 존재하는 경우
    return {"available": True}  # ID가 사용 가능한 경우

# 사용자 생성 API
@router.post("/users/", response_model=UserSchema)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    # 이메일 형식 검증
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, user.email):
        raise HTTPException(status_code=400, detail="유효하지 않은 이메일 형식입니다.")

    # 사용자 중복 확인
    existing_user = db.query(User).filter(User.user_id == user.user_id).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="아이디가 이미 존재합니다.")

    # 비밀번호 해싱
    hashed_password = hash_password(user.password)

    # 사용자 생성
    db_user = User(
        user_id=user.user_id,
        name=user.name,
        email=user.email,
        password=hashed_password,
        phone=user.phone,  # 핸드폰 번호 추가
        address=user.address,  # 주소 추가
        approval_status=user.approval_status,
    )

    db.add(db_user)

    # 권한 추가 (멀티셀렉 지원)
    if user.role_ids:  # role_ids가 제공되면
        for role_id in user.role_ids:  # role_ids가 배열일 경우 반복
            user_role = UserRole(user_id=db_user.user_id, role_id=role_id)
            db.add(user_role)

    # UserSchema에서 roles 속성 포함하여 반환
    user_roles = db.query(UserRole).filter(UserRole.user_id == db_user.user_id).all()
    db_user.roles = user_roles  # roles에 추가된 권한 정보 담기

    db.commit()
    db.refresh(db_user)
    return db_user

# 사용자 수정 API
@router.put("/users/{user_id}", response_model=UserSchema)
def update_user(user_id: str, user_update: UserUpdate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    for key, value in user_update.dict(exclude_unset=True).items(): # exclude_unset=True 입력값이 없는 필드는 변경하지 않음
        setattr(user, key, value)
    db.commit()
    db.refresh(user)
    return user

# 사용자 삭제 API
@router.delete("/api/users/", response_model=dict)
def delete_user(request: UsersRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
   
    users = db.query(User).filter(User.user_id.in_(request.user_ids)).all()

    if not users:
        raise HTTPException(status_code=404, detail="Users not found")

    for user in users:
        db.query(UserRole).filter(UserRole.user_id == user.user_id).delete()
        db.delete(user)

    db.commit()
    return {"message": "Users deleted successfully"}

# 사용자 승인 API
@router.post("/api/users/approve", response_model=dict)
def approve_user(request: UsersRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(User).filter(User.user_id.in_(request.user_ids)).all()

    if not users:
        raise HTTPException(status_code=404, detail="Users not found")

    for user in users:
        user.approval_status = 'Y'  # 승인 상태를 'Y'로 변경
        # 권한 삭제(user_roles) 관련 코드가 필요하면 여기에 추가

    db.commit()
    return {"message": "Users approved successfully"}

# ================================테스트================================

# Users 테이블과 Profile 테이블 inner join
@router.get("/users/join/", response_model=list[UserSchema])
def read_users(db: Session = Depends(get_db)):
    users = (
        db.query(User)
        .join(Profile, User.user_id == Profile.user_id)
        .all()
        )
    return users

# Users 테이블과 Profile 테이블 left outer join
@router.get("/users/outerjoin/", response_model=list[UserSchema])
def read_users(db: Session = Depends(get_db)):
    users = (
        db.query(User)
        .outerjoin(Profile, User.user_id == Profile.user_id)
        .all()
        )
    return users

# Join + Select 특정 컬럼만 조회 
@router.get("/users/", response_model=list[UserSchema])
def read_users(db: Session = Depends(get_db)):
    users = db.query(User.user_id, User.username, Profile.bio).join(Profile, User.user_id == Profile.user_id).all()
    return users

# 트랜잭션 테스트
@router.put("/users/transaction/{user_id}")
def update_user(user_id: str, user_update: UserUpdate, db: Session = Depends(get_db)):
    try:
        # 1️. User 테이블 업데이트
        user = db.query(User).filter(User.user_id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.username = user_update.username
        user.email = user_update.email

        # 2️. Profile 테이블 업데이트
        profile = db.query(Profile).filter(Profile.user_id == user_id).first()
        if profile:
            profile.bio = user_update.bio
            profile.avatar = user_update.avatar
        else:
            # 프로필이 없으면 새로 생성
            new_profile = Profile(user_id=user_id, bio=user_update.bio, avatar=user_update.avatar)
            db.add(new_profile)

        # 3️. 트랜잭션 커밋
        db.commit()
        return {"message": "User and profile updated successfully"}
    
    except Exception as e:
        db.rollback()  # 오류 발생 시 롤백
        raise HTTPException(status_code=500, detail=str(e))
    
    # ================================테스트================================