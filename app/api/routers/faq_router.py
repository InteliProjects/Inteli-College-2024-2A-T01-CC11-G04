import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from llm_service_api.services.faq_service import FAQService

# Set up logging
logger = logging.getLogger(__name__)

router = APIRouter()

models_dir = Path("/app/llm_service_api/temp")

faq_service = FAQService(
    model_name="llama3.2:3b",
    embed_model_name="sentence-transformers/LaBSE",
    collection_name="brastel_faq",
    csv_file_path=Path("/app/resources/dataset/faq.csv"),
    store_path=models_dir,
)


@router.get("/faq/response/")
async def get_faq_response(question: str = Query(..., description="The question for which the FAQ response is needed")):
    try:
        logger.info(f"Received request to generate response for question: {question}")
        response = faq_service.generate_response(question)
        return {"response": response}
    except Exception as e:
        logger.error(f"Error generating response for question: {question} - {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error generating response: {str(e)}")


@router.get("/faq/query/")
async def query_faq(question: str = Query(..., description="The question to query in the FAQ service")):
    try:
        logger.info(f"Received request to query FAQ for question: {question}")
        results = faq_service._query_faq(question)
        return {"results": [result.metadata for result in results]}
    except Exception as e:
        logger.error(f"Error querying FAQ for question: {question} - {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error querying FAQ: {str(e)}")
