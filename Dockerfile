# 
FROM python:3.11

# 
WORKDIR /code

# 
COPY ./requirements.txt /code/requirements.txt

# 
RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r /code/requirements.txt

# 
COPY ./app /code/app

# 
#CMD ["pip", "list"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]