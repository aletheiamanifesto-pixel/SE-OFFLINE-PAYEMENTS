FROM python:3.11-slim

WORKDIR /app

# Copiamo prima il file di packaging per sfruttare la cache dei layer Docker
COPY pyproject.toml ./

# Installiamo le dipendenze (senza il codice sorgente, per cache efficiente)
RUN pip install --no-cache-dir cryptography pytest

# Copiamo il resto del progetto
COPY . .

# Installiamo il pacchetto in modalità editable
RUN pip install --no-cache-dir -e ".[dev]"

# Porta di default (non usata in questa versione CLI, ma utile per futura API)
EXPOSE 8000

# Comando di default: esegui i test
CMD ["python", "-m", "pytest", "tests/", "-v"]
