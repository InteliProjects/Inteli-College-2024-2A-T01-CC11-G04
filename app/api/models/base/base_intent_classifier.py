from abc import ABC, abstractmethod

class BaseIntentClassifier(ABC):
    def __init__(self):
        self.model = self.load_model()

    @abstractmethod
    def load_model(self):
        """Carrega o modelo específico. Deve ser implementado por subclasses."""
        pass

    @abstractmethod
    def predict(self, embeddings):
        """Realiza a predição baseado nos embeddings."""
        pass
