<table>
  <tr>
    <td style="vertical-align: middle;">
      <a href="https://www.brastel.com/"><img src="./artigo/sprint5/img/logo-brastel.png" alt="Brastel Co., Ltd." border="0" width="180"></a>
    </td>
    <td style="vertical-align: middle;">
      <a href="https://www.inteli.edu.br/"><img src="./inteli-logo.png" alt="Inteli - Instituto de Tecnologia e Liderança" border="0" width="30%"></a>
    </td>
  </tr>
</table>

# Introdução

Este é um dos repositórios do projeto de alunos do Inteli em parceria com a Brastel no 2o semestre de 2024.
Este projeto está sendo desenvolvido por alunos do módulo 11 do curso de Ciência da Computação.

# Projeto: Robô Conversacional Otimizado com Processamento de Linguagem Natural (PLN) e Geração de Respostas por IA Generativa

# Grupo: Mockingjay

# Integrantes:

* [Allan Casado](allan.casado@sou.inteli.edu.br)
* [Cristiane Coutinho](cristiane.coutinho@sou.inteli.edu.br)
* [Elias Biondo](elias.biondo@sou.inteli.edu.br)
* [Gábrio Silva](gabrio.silva@sou.inteli.edu.br)
* [Giovana Thomé](giovana.thome@sou.inteli.edu.br)
* [Melyssa Rojas](melyssa.rojas@sou.inteli.edu.br)
* [Rafael Cabral](rafael.cabral@sou.inteli.edu.br)

# Descrição

A Brastel Co., Ltd., fundada em 1996 e sediada em Tóquio, oferece serviços de remessas financeiras no Japão (Brastel Remit) através de um aplicativo multilíngue, atendendo mais de 25 mil clientes mensais via chat online. O projeto tem como objetivo desenvolver um chatbot de inteligência artificial para o SAC utilizando um modelo de classificação de intenção e um modelo de geração de texto, visando aumentar a satisfação dos clientes, melhorar a eficiência dos atendimentos e permitir que os atendentes humanos se concentrem em casos específicos.

# Configuração para desenvolvimento

Primeiramente, para acessar o chatbot via plataforma, os passos são os seguintes (Ambiente Linux):

**1° passo:** Instale o Docker se ainda não estiver instalado na máquina. Certifique-se também de que o ambiente de execução possui uma ou mais GPUs disponíveis e que o Ollama está instalado e em execução. Você pode baixá-lo em [https://ollama.com/download](https://ollama.com/download).

---

**2° passo:** Faça o download do modelo `llama3.2:3b` usando o Ollama. Execute o seguinte comando no terminal:

```bash
ollama pull llama3.2:3b
```

---

**3° passo:** Configure o Ollama para permitir conexões externas. Edite o arquivo de serviço do Ollama:

```bash
sudo nano /etc/systemd/system/ollama.service
```

Dentro da seção `[Service]`, adicione a seguinte linha (pode haver múltiplas variáveis de ambiente `Environment=`):

```ini
Environment="OLLAMA_HOST=0.0.0.0:11434"
```

Salve o arquivo e reinicie o serviço do Ollama:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ollama
```

---

**4° passo:** Navegue até a pasta "app" na raiz do repositório para encontrar o arquivo **docker-compose.yaml**:

```bash
cd app
```

---

**5° passo:** No terminal, dentro do diretório onde está o arquivo acima, execute o comando para iniciar os serviços:

```bash
docker-compose up
```

---

**6° passo:** Com os serviços em execução, será possível acessar os seguintes endereços:

- **Frontend**: Acesse no navegador em [http://localhost:3000](http://localhost:3000)
- **Intent API**: Acesse em [http://localhost:8000](http://localhost:8000)
- **RAG API**: Acesse em [http://localhost:8001](http://localhost:8001)
- **Web API**: Acesse em [http://localhost:4000](http://localhost:4000)

---

Outrora, se houver apenas a intenção de ter acesso aos notebooks de desenvolvimento, os passos são os seguintes:

Caminhe até a pasta abaixo:

```
notebooks\sprint5
```

Neste caminho, haverá diferentes notebooks com seus próprios propósitos, cabe o desenvolvedor esccolher de acordo com sua necessidade. Os notebooks tem estes comportamentos:

- **Implementacao_de_Modelo_Baseline_Funcao_Bow**: Implementação de uma abordagem de vetorização usando o Bow;
- **Implementacao_de_Modelo_LLM_ou_Bert**: Implementação do modelo de geração de texto usando um modelo LLM e RAG;
- **Implementacao_de_Modelo_LSTM_ou_RNN**: Implementação do modelo classificador de intenção usando LSTM;
- **Implementacao_de_Modelo_Rede_Neural_Word2vec**: Implementação de modelo classificador de intenção com vetorização Word2Vec;
- **exploratory_analysis**: Análise exploratória para a base dados;
- **pre_processing_pipeline**: Pipeline usada para o tratamento dos dados;
- **Avaliacao_Metricas_RAG**: Implementação da técnica de RAG com métricas;

É importante ressaltar que todos os notebooks podem ser executados no **Jupyter Notebook** e em editores de código compatíveis com o formato de arquivo, como o **Visual Studio Code (VSCode)**. Além disso, é possível rodar os notebooks online no **Google Colab**.

# Tags

- [SPRINT 1](https://github.com/Inteli-College/2024-2A-T01-CC11-G04/releases/tag/SPRINT1):
  - Pipeline de Processamento e Base de Dados;
  - Draft do Artigo;
  - Apresentação da SPRINT 1;

- [SPRINT 2](https://github.com/Inteli-College/2024-2A-T01-CC11-G04/releases/tag/SPRINT2):
  - Implementação de Modelo Baseline (BoW com NB);
  - Implementação de Modelo com Rede Neural e Word2Vec pré-treinado;
  - Artigo com Avaliação Inicial de Modelos de Classificação de Texto;
  - Apresentação da SPRINT 2;

- [SPRINT 3](https://github.com/Inteli-College/2024-2A-T01-CC11-G04/releases/tag/SPRINT3):
  - Implementação de Modelo LSTM ou RNN;
  - Artigo com Avaliação de Modelo LSTM ou RNN;
  - Apresentação da SPRINT 3;

- [SPRINT 4](https://github.com/Inteli-College/2024-2A-T01-CC11-G04/releases/tag/SPRINT4):
  - Implementação de Modelo LLM ou BERT;
  - Artigo com Avaliação de Modelo LLM ou BERT;
  - Apresentação da SPRINT 3;
 
- [SPRINT 5](https://github.com/Inteli-College/2024-2A-T01-CC11-G04/releases/tag/SPRINT5):
  - Implementação Final;
  - Implementação de Desafio;
  - Artigo Final;
  - Apresentação Final;

# Licença

<img src="https://mirrors.creativecommons.org/presskit/icons/cc.large.png" alt="CC Logo" width="150"/><br>

<img src="https://mirrors.creativecommons.org/presskit/icons/by.large.png" alt="CC BY Logo" width="150"/>

[Application 4.0 International](https://creativecommons.org/licenses/by/4.0/?ref=chooser-v1)
