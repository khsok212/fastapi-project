from passlib.context import CryptContext

# 비밀번호 해싱을 위한 패스리브 컨텍스트 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain_password: str) -> str:
    """
    주어진 평문 비밀번호를 해시합니다.
    
    :param plain_password: 평문 비밀번호
    :return: 해시된 비밀번호
    """
    return pwd_context.hash(plain_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    평문 비밀번호와 해시된 비밀번호를 비교하여 일치하는지 검증합니다.
    
    :param plain_password: 평문 비밀번호
    :param hashed_password: 해시된 비밀번호
    :return: 일치 여부 (True 또는 False)
    """
    return pwd_context.verify(plain_password, hashed_password)
