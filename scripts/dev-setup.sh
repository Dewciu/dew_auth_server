#!/bin/bash
# Development setup script for Dew Auth Server

set -e

# Default values
SETUP_CERTS=true
START_DEPENDENCIES=true
BUILD_SERVER=true
FRESH_DB=false
START_SERVER=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --no-certs)
      SETUP_CERTS=false
      shift
      ;;
    --no-deps)
      START_DEPENDENCIES=false
      shift
      ;;
    --no-build)
      BUILD_SERVER=false
      shift
      ;;
    --fresh-db)
      FRESH_DB=true
      shift
      ;;
    --start)
      START_SERVER=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [OPTIONS]"
      echo "Set up a development environment for Dew Auth Server."
      echo ""
      echo "Options:"
      echo "  --no-certs           Skip certificate generation"
      echo "  --no-deps            Don't start dependencies (PostgreSQL, Redis)"
      echo "  --no-build           Skip building the server"
      echo "  --fresh-db           Reset database (WARNING: THIS DELETES ALL DATA)"
      echo "  --start              Start the server after setup"
      echo "  --help, -h           Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Make sure we have an .env file
if [ ! -f ".env" ]; then
  if [ -f ".env.template" ]; then
    echo "Creating .env file from template..."
    cp .env.template .env
  else
    echo "Error: .env file not found and .env.template is missing."
    exit 1
  fi
fi

# Set up certificates
if [ "$SETUP_CERTS" = true ]; then
  echo "Setting up development certificates..."
  mkdir -p certs
  
  if [ ! -f "certs/cert.pem" ] || [ ! -f "certs/key.pem" ]; then
    echo "Generating self-signed certificates..."
    openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=localhost"
    echo "Certificates generated successfully."
  else
    echo "Certificates already exist. Skipping generation."
  fi
fi

# Start dependencies
if [ "$START_DEPENDENCIES" = true ]; then
  echo "Starting dependencies (PostgreSQL and Redis)..."
  
  # Check if Docker is running
  if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is not running or not installed."
    exit 1
  fi
  
  # Handle database reset if requested
  if [ "$FRESH_DB" = true ]; then
    echo "Removing existing database volumes..."
    docker-compose down -v
  fi
  
  # Start the dependencies
  docker-compose up -d db redis
  
  echo "Waiting for services to be ready..."
  sleep 5
  
  # Check if PostgreSQL is running
  if ! docker-compose exec db pg_isready -U dew_auth >/dev/null 2>&1; then
    echo "Error: PostgreSQL is not ready. Check logs with 'docker-compose logs db'."
    exit 1
  fi
  
  # Check if Redis is running
  if ! docker-compose exec redis redis-cli ping >/dev/null 2>&1; then
    echo "Error: Redis is not ready. Check logs with 'docker-compose logs redis'."
    exit 1
  fi
  
  echo "Dependencies are running."
fi

# Build the server
if [ "$BUILD_SERVER" = true ]; then
  echo "Building Dew Auth Server..."
  go build -o ./tmp/main ./cmd/main.go
  echo "Build completed successfully."
fi

# Start the server if requested
if [ "$START_SERVER" = true ]; then
  echo "Starting Dew Auth Server..."
  
  # Kill any existing server process
  if [ -f "./.pid" ]; then
    OLD_PID=$(cat ./.pid)
    if kill -0 $OLD_PID >/dev/null 2>&1; then
      echo "Stopping existing server process (PID: $OLD_PID)..."
      kill $OLD_PID
      sleep 2
    fi
  fi
  
  # Start the server in the background
  ./tmp/main &
  SERVER_PID=$!
  echo $SERVER_PID > ./.pid
  
  echo "Server started with PID: $SERVER_PID"
  echo "To stop the server, run: kill $(cat ./.pid)"
fi

echo "Development setup complete!"