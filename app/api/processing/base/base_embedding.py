from abc import ABC, abstractmethod

class BaseEmbedding(ABC):
    @abstractmethod
    def embed(self, text: str):
        """Gera e retorna os embeddings para o texto fornecido."""
        pass
