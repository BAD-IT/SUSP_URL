FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /scanner

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner.py .

CMD ["python", "scanner.py"]
