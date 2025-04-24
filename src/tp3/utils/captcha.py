from src.tp3.utils.config import logger
import requests
import pytesseract
from PIL import Image
from io import BytesIO
import re

class Captcha:
    def __init__(self, url):
        self.url = "http://31.220.95.27:9002/captcha.php"
        self.image = None
        self.value = ""

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        response = requests.get(self.url)
        if response.status_code == 200:
            self.image = Image.open(BytesIO(response.content))
        else:
            logger.info(f"Captcha non trouvé : {response.status_code}")

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        if self.image is None:
            logger.info("Image not captured.")
            return

        raw_text = pytesseract.image_to_string(self.image)
        digits = re.findall(r'\d+', raw_text)
        if digits:
            self.value = digits[0]
        else:
            self.value = "UNREADABLE"

        logger.info(f"[Captcha Solver] OCR Output: {self.value}")

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
