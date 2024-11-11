import re
import string
import spacy
from enum import Enum
from abc import ABC, abstractmethod
from typing import List, Type, Union
from spacy.lang.xx import MultiLanguage
from api.processing.base.base_text_processor import BasePreprocessingPipeline, BaseTextProcessor

class NLPLibrary(Enum):
    spacy = 1

class PreprocessingTextPipeline(BasePreprocessingPipeline):
    def __init__(self, nlpLibrary: NLPLibrary = NLPLibrary.spacy):
        self.steps = []
        self.nlpLibrary = nlpLibrary
        self.add_step(RemoveEscapeSequences())
        self.add_step(Lowercase())
        self.add_step(RemoveNumbers())
        self.add_step(RemovePunctuation())
        self.add_step(Tokenization())

    def add_step(self, step: BaseTextProcessor):
        for required_step in step.requires():
            if not any(isinstance(s, required_step) for s in self.steps):
                raise ValueError(f"{step.__class__.__name__} requires {required_step.__name__} to be added first.")
        self.steps.append(step)

    def run(self, data: Union[str, List[str]]) -> Union[str, List[str]]:
        for step in self.steps:
            data = step.execute(data)
        return data

class RemoveEscapeSequences(BaseTextProcessor):
    def execute(self, data: str) -> str:
        return data.translate(str.maketrans({'\n': ' ', '\t': ' ', '\r': ' '}))

    def requires(self) -> List[Type[BaseTextProcessor]]:
        return []

class Lowercase(BaseTextProcessor):
    def execute(self, data: str) -> str:
        return data.lower()

    def requires(self) -> List[Type[BaseTextProcessor]]:
        return []

class RemoveNumbers(BaseTextProcessor):
    def execute(self, data: str) -> str:
        return re.sub(r'\d+', '', data)

    def requires(self) -> List[Type[BaseTextProcessor]]:
        return []

class RemovePunctuation(BaseTextProcessor):
    def execute(self, data: str) -> str:
        translator = str.maketrans('', '', string.punctuation)
        return data.translate(translator)

    def requires(self) -> List[Type[BaseTextProcessor]]:
        return []

class Tokenization(BaseTextProcessor):
    def execute(self, data: str) -> List[str]:
        nlp = MultiLanguage()
        tokens = nlp.tokenizer(data)
        return [token.text for token in tokens]

    def requires(self) -> List[Type[BaseTextProcessor]]:
        return []

class RemoveStopwords(BaseTextProcessor):
    def execute(self, data: List[str]) -> List[str]:
        nlp = spacy.load("pt_core_news_sm")
        doc = nlp.make_doc(" ".join(data))
        return [token.text for token in doc if not token.is_stop]

    def requires(self) -> List[Type[BaseTextProcessor]]:
        return [Tokenization]

class Lemmatization(BaseTextProcessor):
    def execute(self, data: List[str]) -> List[str]:
        nlp = spacy.load("pt_core_news_sm")
        doc = nlp(" ".join(data))
        return [token.lemma_ for token in doc]

    def requires(self) -> List[Type[BaseTextProcessor]]:
        return [Tokenization, RemoveStopwords]

if __name__ == "__main__":
    pipeline = PreprocessingTextPipeline(NLPLibrary.spacy)

    pipeline.add_step(RemoveEscapeSequences())
    pipeline.add_step(Lowercase())
    pipeline.add_step(RemovePunctuation())
    pipeline.add_step(Tokenization())

    sample_text = "Este é um Texto Exemplo, com números 123 e pontuação!!!"
    processed_text = pipeline.run(sample_text)
    print(processed_text)
