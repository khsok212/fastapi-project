import logging

def setup_logging():
    # 로깅 설정
    logging.basicConfig(
        level=logging.INFO,  # 로깅 레벨 설정 (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # 로그 출력 형식
        handlers=[
            logging.FileHandler("T:/khs/work/log/app.log"),  # 파일 핸들러: 로그를 파일에 저장
            logging.StreamHandler()  # 콘솔 핸들러: 로그를 콘솔에 출력
        ]
    )
