# Set base image (host OS)
FROM python:3.12-alpine

# By default, listen on port 5000
EXPOSE 5000/tcp

# Set the working directory in the container
WORKDIR /app

# Copy everything into the working directory
COPY *.txt *.py *.html Dockerfile  ./

# Install any dependencies
RUN pip install -r requirements.txt

# Specify the command to run on container start
CMD ["python", "app.py"]