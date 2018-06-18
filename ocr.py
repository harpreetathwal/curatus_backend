import sys
import requests
import pytesseract

from PIL import Image
from io import BytesIO


def get_image(url):
    return Image.open(BytesIO(requests.get(url).content))

    """Tool to test the raw output of pytesseract with a given input URL"""
def ocr(url):
    print("A simple OCR utility\n")
    image = get_image(url)
    f = open("./uploads/text_output.txt","w+")
    f.write("The raw output from tesseract with no processing is:\n\n")
    f.write("-----------------BEGIN-----------------\n")
    f.write(pytesseract.image_to_string(image))
    f.write("------------------END------------------\n")
    f.close()
    f = open("./uploads/text_output.txt","r")
    text = f.read()
    f.close()
    return text
    
if __name__ == '__main__':
    sys.stdout.write("""
===OOOO=====CCCCC===RRRRRR=====\n
==OO==OO===CC=======RR===RR====\n
==OO==OO===CC=======RR===RR====\n
==OO==OO===CC=======RRRRRR=====\n
==OO==OO===CC=======RR==RR=====\n
==OO==OO===CC=======RR== RR====\n
===OOOO=====CCCCC===RR====RR===\n\n
""")
    sys.stdout.write("A simple OCR utility\n")
    url = input("What is the url of the image you would like to analyze?\n")
    image = get_image(url)
    sys.stdout.write("The raw output from tesseract with no processing is:\n\n")
    sys.stdout.write("-----------------BEGIN-----------------\n")
    sys.stdout.write(pytesseract.image_to_string(image) + "\n")
    sys.stdout.write("------------------END------------------\n")
