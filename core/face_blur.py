# core/face_blur.py
# pip install opencv-python
import cv2

def blurred_preview(src_path: str, dst_path: str, blur=35):
    img = cv2.imread(src_path)
    if img is None:
        return False
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    face = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
    faces = face.detectMultiScale(gray, 1.2, 5)
    for (x, y, w, h) in faces:
        roi = img[y:y+h, x:x+w]
        roi = cv2.GaussianBlur(roi, (blur|1, blur|1), 0)
        img[y:y+h, x:x+w] = roi
    cv2.imwrite(dst_path, img)
    return True
