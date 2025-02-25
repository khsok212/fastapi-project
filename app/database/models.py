from sqlalchemy import Column, String, Integer, ForeignKey, TIMESTAMP, CHAR
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    user_id = Column(String, primary_key=True)  # 회원 고유 ID (문자열 형식)
    name = Column(String, nullable=False)         # 이름
    email = Column(String, nullable=False)  # 이메일 (중복 불가)
    password = Column(String, nullable=False)     # 비밀번호 (해싱 필요)
    phone = Column(String)                         # 전화번호
    address = Column(String)                         # 전화번호
    approval_status = Column(CHAR(1), default='N')  # 승인 여부 ('Y' = 승인, 'N' = 미승인)
    created_at = Column(TIMESTAMP, server_default='CURRENT_TIMESTAMP')  # 가입일

    # User Roles 관계 설정
    roles = relationship("UserRole", back_populates="user")

class Role(Base):
    __tablename__ = 'roles'
    
    role_id = Column(Integer, primary_key=True, autoincrement=True)  # 권한 고유 ID
    role_name = Column(String, unique=True, nullable=False)            # 권한 유형 (예: 'admin', 'user', 'editor')

    # User Roles 관계 설정
    user_roles = relationship("UserRole", back_populates="role")

class UserRole(Base):
    __tablename__ = 'user_roles'
    
    user_role_id = Column(Integer, primary_key=True, autoincrement=True)  # 회원 권한 ID
    user_id = Column(String, ForeignKey('users.user_id'), nullable=False)   # 회원 ID (TEXT 타입)
    role_id = Column(Integer, ForeignKey('roles.role_id'), nullable=False)   # 권한 ID

    # 관계 설정
    user = relationship("User", back_populates="roles")
    role = relationship("Role", back_populates="user_roles")

class UserHistory(Base):
    __tablename__ = 'user_history'
    
    history_id = Column(Integer, primary_key=True, autoincrement=True)  # 이력 고유 ID
    user_id = Column(String, ForeignKey('users.user_id'))                # 회원 ID (TEXT 타입)
    login_time = Column(TIMESTAMP, server_default='CURRENT_TIMESTAMP')    # 접속 일시
    login_ip = Column(String)                                              # 접속한 IP 주소

    user = relationship("User")

