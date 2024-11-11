# Use uma imagem oficial do Python como base
FROM python:3.9-slim

# Defina o diretório de trabalho para /app no contêiner
WORKDIR /app

# Copie o arquivo de dependências (requirements.txt) para o diretório de trabalho
COPY requirements.txt .

# Instale as dependências
RUN pip install -r requirements.txt

# Copie o restante da aplicação para o diretório de trabalho (incluindo a pasta api)
COPY . /app

# Exponha a porta 8000 para o Uvicorn
EXPOSE 8000

# Comando para rodar a aplicação FastAPI usando Uvicorn
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
