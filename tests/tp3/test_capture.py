from src.tp3.utils.captcha import Captcha
from src.tp3.utils.config import logger

def main():
    logger.info("🚀 Starting CAPTCHA test...")

    captcha = Captcha(url="http://31.220.95.27:9002/captcha.php")
    captcha.capture()
    captcha.solve()

    value = captcha.get_value()
    logger.info(f"✅ Captured CAPTCHA value: {value}")

if __name__ == "__main__":
    main()
