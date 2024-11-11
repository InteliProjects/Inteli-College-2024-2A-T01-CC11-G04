import logging
from pathlib import Path
import chromadb
import pandas as pd
from llama_index.core import Settings, Document, VectorStoreIndex
from llama_index.core.storage.storage_context import StorageContext
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.llms.ollama import Ollama
from llama_index.vector_stores.chroma import ChromaVectorStore

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FAQService:
    """
    Service to handle Frequently Asked Questions (FAQ) using a vector store index
    for efficient question-answer retrieval.
    """

    def __init__(self, model_name: str, embed_model_name: str, collection_name: str, csv_file_path: Path,
                 store_path: Path):
        """
        Initializes the FAQService with an LLM, embedding model, vector store, and data storage context.
        """
        try:
            logger.info("Initializing FAQService...")
            self.llm = Ollama(model=model_name, request_timeout=120.0, base_url="http://host.docker.internal:11434")
            Settings.llm = self.llm
            Settings.embed_model = HuggingFaceEmbedding(model_name=embed_model_name, cache_folder=store_path.as_posix())

            # Set up the Chroma Vector Store
            client = chromadb.Client()
            chroma_collection = client.create_collection(name=collection_name)
            vector_store = ChromaVectorStore(chroma_collection=chroma_collection)

            # Set up the Storage Context
            self.storage_context = StorageContext.from_defaults(vector_store=vector_store)
            self.csv_file_path = csv_file_path

            # Create Vector Index
            self.index = self._create_vector_index()

            logger.info("FAQService initialization complete.")
        except Exception as e:
            logger.error(f"Error initializing FAQService: {str(e)}")
            raise

    def _load_data(self, csv_path: Path):
        """
        Loads data from a CSV file and converts it into a list of Document objects.
        """
        try:
            logger.info(f"Loading data from {csv_path}")
            df = pd.read_csv(csv_path)
            documents = []

            # Iterate over the rows of the dataframe to create documents
            for index, row in df.iterrows():
                question = str(row['question']).strip()
                answer = str(row['answer']).strip()
                content = f"Pergunta: {question}\nResposta: {answer}"
                doc = Document(text=content, metadata={"Pergunta": question, "Resposta": answer, "ID": index})
                documents.append(doc)

            logger.info(f"Loaded {len(documents)} documents from {csv_path}")
            return documents
        except Exception as e:
            logger.error(f"Error loading data from {csv_path}: {str(e)}")
            raise

    def _create_vector_index(self):
        """
        Creates a vector index from FAQ documents loaded from the CSV file.
        """
        try:
            logger.info("Creating vector index...")
            documents = self._load_data(self.csv_file_path)
            index = VectorStoreIndex.from_documents(documents, service_context=Settings, storage_context=self.storage_context)
            logger.info("Vector index created successfully.")
            return index
        except Exception as e:
            logger.error(f"Error creating vector index: {str(e)}")
            raise

    def _query_faq(self, question: str):
        """
        Queries the FAQ vector index to retrieve the most relevant answers.
        """
        try:
            logger.info(f"Querying FAQ for question: {question}")
            retriever = self.index.as_retriever()
            results = retriever.retrieve(question)
            logger.info(f"Retrieved {len(results)} results for question: {question}")
            return results
        except Exception as e:
            logger.error(f"Error querying FAQ: {str(e)}")
            raise

    def generate_response(self, question: str):
        """
        Generates a response based on the retrieved FAQ answers and LLM completion.
        """
        try:
            logger.info(f"Generating response for question: {question}")
            results = self._query_faq(question)

            # Construct the context from retrieved results
            context_list = [str(n.metadata) for n in results]
            prompt = (
                "Você agora está personificando um Assistente feliz e prestativo da Brastel Remit.\n"
                "Usando as referências abaixo, forneça uma resposta direta e natural à pergunta do usuário em português.\n"
                "Certifique-se de que a resposta esteja gramaticalmente correta e flua naturalmente em português.\n"
                "Para melhorar a resposta, cite o número da 'Resposta' que aborda a pergunta do usuário e a referência completa entre aspas.\n"
                "Responda à pergunta do usuário DIRETAMENTE de forma concisa e respeitosa.\n"
                "Apenas faça referência a respostas que sejam realmente relevantes para a pergunta do usuário. Para garantir isso, avalie cada referência quanto à sua relevância para a pergunta do usuário em uma escala de 1 a 10, e responda apenas com as que têm uma pontuação de **8 ou superior**.\n"
                "Somente forneça uma resposta se a referência abordar direta e completamente a pergunta do usuário. Se a referência apenas corresponder parcialmente ou se a relevância for baixa, **não a considere relevante**.\n"
                "Se você não encontrar nenhuma resposta relevante para a pergunta do usuário, apenas informe que não conseguiu encontrar uma resposta válida.\n"
                "Verifique os dados e use apenas respostas que abordem diretamente a pergunta do usuário.\n"
                "Não mostre ou faça referência a quaisquer perguntas que não sejam relevantes para a pergunta do usuário. Tenha certeza disso!!!\n"
                "Exemplo: Pergunta: Olá, tudo bem? Resposta: Oi, tudo ótimo! Como posso ajudar você hoje? Sou o assistente da Brastel Remit.\n"
                "Exemplo: Pergunta: Preciso de ajuda Resposta: Claro! Em que posso ser útil? Sou o assistente da Brastel Remit.\n"
                "Exemplo: Pergunta: Como faço para enviar dinheiro? Resposta: De acordo com a Resposta 1, você pode enviar dinheiro para seus amigos e familiares no exterior usando nosso serviço online.\n"
                "Exemplo: Pergunta: Quais são as taxas de inscrição? Resposta: Conforme a Resposta 3, não há taxas de inscrição ou custos anuais de adesão.\n"
                "Exemplo (Se não houver resposta relevante): Não consegui encontrar uma resposta válida para sua pergunta. Poderia reformulá-la, por favor?\n"
                "Exemplo (Se não houver resposta relevante): Desculpe, não encontrei informações relevantes para sua pergunta. Há algo mais em que eu possa ajudar?\n"
                "Exemplo (Se não houver resposta relevante): Infelizmente, não tenho uma resposta para sua pergunta no momento. Poderia fornecer mais detalhes?\n"
                "Pergunta e intenção do Usuário: " + question + "\n"
                "Dados para responder:\n\n"
                + "\n\n".join(context_list)
            )

            # Generate the response using the LLM
            response = self.llm.complete(prompt)
            logger.info(f"Generated response for question: {question}")
            return str(response)
        except Exception as e:
            logger.error(f"Error generating response: {str(e)}", exc_info=True)
            raise
