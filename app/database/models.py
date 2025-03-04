from sqlalchemy import Column, String, Integer, ForeignKey, TIMESTAMP, Text, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    user_id = Column(String, primary_key=True)  # 회원 고유 ID
    name = Column(String, nullable=False)  # 이름
    email = Column(String, nullable=False, unique=True)  # 이메일 (중복 불가)
    password = Column(String, nullable=False)  # 비밀번호 (해싱 필요)
    phone = Column(String)  # 전화번호
    address1 = Column(String)  # 주소1
    address2 = Column(String)  # 주소2(상세주소)
    approval_status = Column(String(1), default='N')  # 승인 여부 ('Y' = 승인, 'N' = 미승인)
    created_at = Column(TIMESTAMP, server_default='CURRENT_TIMESTAMP')  # 가입일

    roles = relationship("UserRole", back_populates="user")


class Role(Base):
    __tablename__ = 'roles'
    
    role_id = Column(Integer, primary_key=True, autoincrement=True)
    role_name = Column(String, unique=True, nullable=False)

    user_roles = relationship("UserRole", back_populates="role")


class UserRole(Base):
    __tablename__ = 'user_roles'
    
    user_role_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)
    role_id = Column(Integer, ForeignKey('roles.role_id'), nullable=False)

    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="user_roles")


class UserHistory(Base):
    __tablename__ = 'user_history'
    
    history_id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, ForeignKey('users.user_id'))
    login_time = Column(TIMESTAMP, server_default=func.now(), nullable=False)
    login_ip = Column(String, nullable=False)
    request_path = Column(String, nullable=False)  # 요청 경로 (예: "POST /login/")
    memo = Column(Text, default='')  # 추가 메모 (기본값: 빈 문자열)

    user = relationship("User")

class Blacklist(Base):
    __tablename__ = 'blacklist'
    
    ip_address = Column(String, primary_key=True)  # 차단된 IP 주소를 기본 키로 설정
    user_id = Column(String, ForeignKey('users.user_id'), nullable=True)  # 선택적 사용자 ID
    created_at = Column(TIMESTAMP, server_default=func.now(), nullable=False)  # 생성일
