import numpy as np
import requests
import os
import zipfile
from gensim.models import KeyedVectors
from api.processing.base.base_embedding import BaseEmbedding

class Word2VecEmbedding(BaseEmbedding):
    def __init__(self):
        self.model = self._load_model()

    def _download_and_extract_model(self, url, zip_path, extract_to='.'):
        os.makedirs(extract_to, exist_ok=True)

        if not os.path.exists(zip_path):
            print(f'Downloading model from {url}...')
            response = requests.get(url)
            with open(zip_path, 'wb') as f:
                f.write(response.content)
            print(f"Model downloaded to {zip_path}")
        if os.path.exists(extract_to):
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)

    def _load_model(self):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))  
        model_dir = os.path.join(base_dir, 'resources', 'word2vec')  
        model_file = os.path.join(model_dir, 'w2v.vectors.kv')  
        zip_file = "w2v.vectors.zip"
        zip_path = os.path.join(model_dir, zip_file)

        if not os.path.exists(model_file):
            self._download_and_extract_model(
                'https://github.com/rdenadai/WordEmbeddingPortugues/releases/download/0.5/w2v.vectors.zip',
                zip_path,
                extract_to=model_dir
            )

        model = KeyedVectors.load(model_file, mmap='r')
        return model

    def get_vector(self, word):
        if word in self.model:
            return self.model[word]
        else:
            return None

    def embed(self, text: list[str]):
        embeddings = [self.get_vector(word) for word in text.split(',') if self.get_vector(word) is not None]
        return np.mean(embeddings, axis=0) if embeddings else np.zeros(self.model.vector_size)

if __name__ == "__main__":
    embedding_model = Word2VecEmbedding()
    embeddings = embedding_model.embed("Este,é,um,exemplo,de,texto")
    print(embeddings)
