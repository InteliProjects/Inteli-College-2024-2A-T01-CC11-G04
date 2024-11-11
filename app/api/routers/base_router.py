from fastapi import APIRouter, HTTPException
from api.models.intent_classifiers.specific_intent_classifier import IntentClassifier
from api.models.text_generators.specific_text_generator import SpecificTextGenerator
from api.processing.text_processors.default_pipeline import PreprocessingTextPipeline
from api.processing.embeddings.word2vec import Word2VecEmbedding

router = APIRouter()

intent_classifier = IntentClassifier()
print("Intent classifier loaded")
text_generator = SpecificTextGenerator(model=None)
print("Text generator loaded")
embedding_model = Word2VecEmbedding()
print("Embedding model loaded")
pipeline = PreprocessingTextPipeline()
print("Pipeline loaded")


@router.get("/health")
async def health_check():
    return {"status": "ok"}

@router.post("/embed")
async def classify_intent(text: str):
    processed_text = pipeline.run(text)
    str_processed = ",".join(processed_text)
    embeddings = embedding_model.embed(str_processed)
    return {
        "input_processed": str_processed,
        "embedding": embeddings.tolist(),
    }

@router.post("/intent")
async def classify_intent(text: str):
    processed_text = pipeline.run(text)
    str_processed = ",".join(processed_text)
    embeddings = embedding_model.embed(str_processed)
    intent = intent_classifier.predict(embeddings)
    return {
        "input_processed": str_processed,
        "intent_name": intent,
    }

@router.post("/generate")
async def generate_text(prompt: str):
    try:
        generated_text = text_generator.generate(prompt)
        return {"response": generated_text}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print("Exemplo de uso do router da API.")
