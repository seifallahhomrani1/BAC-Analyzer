FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the analyzer code
COPY bac-analyzer/ ./analyzer/

# Copy the API code
COPY api/ ./api/

# Expose port
EXPOSE 5000

# Run the API
CMD ["python", "api/app.py"]