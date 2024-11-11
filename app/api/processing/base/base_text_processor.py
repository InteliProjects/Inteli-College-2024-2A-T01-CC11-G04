from abc import ABC, abstractmethod
from typing import List, Union, Type

# Abstração para uma etapa de processamento de texto
class BaseTextProcessor(ABC):
    @abstractmethod
    def execute(self, data: Union[str, List[str]]) -> Union[str, List[str]]:
        pass

    @abstractmethod
    def requires(self) -> List[Type['BaseTextProcessor']]:
        pass

class BasePreprocessingPipeline(ABC):
    def __init__(self):
        self.steps = []

    def add_step(self, step: BaseTextProcessor):
        for required_step in step.requires():
            if not any(isinstance(s, required_step) for s in self.steps):
                raise ValueError(f"{step.__class__.__name__} requer a adição prévia de {required_step.__name__}.")
        self.steps.append(step)

    @abstractmethod
    def run(self, data: Union[str, List[str]]) -> Union[str, List[str]]:
        pass
