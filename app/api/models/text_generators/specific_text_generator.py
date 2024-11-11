from api.models.base.base_text_generator import BaseTextGenerator
from fastapi import HTTPException
import requests

class SpecificTextGenerator(BaseTextGenerator):
    def load_model(self, model):
        pass

    def generate(self, prompt):
        try:
            faq_api_url = "http://localhost:8000/faq/"
            response = requests.get(faq_api_url, params={"question": prompt})

            response.raise_for_status()  # Raises an exception for 4xx/5xx errors
            return response.json()["response"]
        except requests.exceptions.RequestException as e:
            raise HTTPException(status_code=500, detail=f"Error fetching response from FAQ API: {e}")
