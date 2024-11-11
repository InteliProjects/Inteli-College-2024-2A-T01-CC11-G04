from abc import ABC, abstractmethod

class BaseTextGenerator(ABC):
    def __init__(self, model):
        self.model = self.load_model(model)

    @abstractmethod
    def load_model(self, model):
        """Carrega o modelo específico. Deve ser implementado por subclasses."""
        pass

    @abstractmethod
    def generate(self, prompt):
        """Gera texto baseado no prompt."""
        pass
