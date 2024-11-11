FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .

# Install dependencies
RUN pip install -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . /app

# Expose the port the app runs on
EXPOSE 8000

# Command to run the FastAPI app with Uvicorn
CMD ["uvicorn", "web_api.main:app", "--host", "0.0.0.0", "--port", "8000"]