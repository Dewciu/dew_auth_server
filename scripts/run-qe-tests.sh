#!/bin/bash
# Script to run Quality Engineering tests against the Dew Auth Server

set -e  # Exit on any error

# Default values
SERVER_URL="https://localhost:8050"
CONFIG_FILE="../qe/config/default.json"
REPORT_PATH="./qe-test-report.html"
TEST_FILTER=""
MARKERS=""
SERVER_START=false
SERVER_WAIT=10
CONTAINER_START=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --url)
      SERVER_URL="$2"
      shift 2
      ;;
    --config)
      CONFIG_FILE="$2"
      shift 2
      ;;
    --report)
      REPORT_PATH="$2"
      shift 2
      ;;
    --filter|-k)
      TEST_FILTER="$2"
      shift 2
      ;;
    --markers|-m)
      MARKERS="$2"
      shift 2
      ;;
    --start-server)
      SERVER_START=true
      shift
      ;;
    --server-wait)
      SERVER_WAIT="$2"
      shift 2
      ;;
    --start-containers)
      CONTAINER_START=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [OPTIONS]"
      echo "Run Quality Engineering tests against the Dew Auth Server."
      echo ""
      echo "Options:"
      echo "  --url URL                    URL of the server (default: https://localhost:8050)"
      echo "  --config FILE                Path to config file (default: ./qe/config/default.json)"
      echo "  --report PATH                Path to save HTML report (default: ./qe-test-report.html)"
      echo "  --filter, -k FILTER          Filter tests by name"
      echo "  --markers, -m MARKERS        Only run tests with specific markers"
      echo "  --start-server               Start the server before running tests"
      echo "  --server-wait SECONDS        Seconds to wait for server to start (default: 10)"
      echo "  --start-containers           Start the database and Redis containers"
      echo "  --help, -h                   Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Check if we need Python dependencies
if ! pip list | grep -q "pytest"; then
  echo "Installing Python dependencies..."
  pip install -r requirements.txt
fi

# Start containers if requested
if [ "$CONTAINER_START" = true ]; then
  echo "Starting database and Redis containers..."
  docker-compose up -d db redis
  
  # Wait for containers to be ready
  echo "Waiting for containers to be ready..."
  sleep 5
fi

# Start server if requested
if [ "$SERVER_START" = true ]; then
  echo "Building and starting Dew Auth Server..."
  
  # Generate certificates if they don't exist
  if [ ! -f "certs/cert.pem" ] || [ ! -f "certs/key.pem" ]; then
    mkdir -p certs
    openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=localhost"
  fi
  
  # Build and start the server
  go build -o ./tmp/main ./cmd/main.go
  
  # Start server in the background
  ./tmp/main &
  SERVER_PID=$!
  
  # Set a trap to kill the server on script exit
  trap "kill $SERVER_PID > /dev/null 2>&1 || true" EXIT
  
  echo "Waiting $SERVER_WAIT seconds for server to start..."
  sleep $SERVER_WAIT
fi

# Set environment variables for tests
export DEW_TEST_SERVER_URL="$SERVER_URL"
export DEW_TEST_CONFIG_FILE="$CONFIG_FILE"
export DEW_TEST_VERIFY_SSL="false"

# Build pytest command
PYTEST_CMD="pytest"

if [ -n "$TEST_FILTER" ]; then
  PYTEST_CMD="$PYTEST_CMD -k \"$TEST_FILTER\""
fi

if [ -n "$MARKERS" ]; then
  PYTEST_CMD="$PYTEST_CMD -m \"$MARKERS\""
fi

# Add report flag if specified
PYTEST_CMD="$PYTEST_CMD -v --report=\"$REPORT_PATH\" tests/"

# Run tests
echo "Running QE tests with command: $PYTEST_CMD"
eval $PYTEST_CMD

# Show results summary
if [ -f "$REPORT_PATH" ]; then
  echo "Test report generated: $REPORT_PATH"
else
  echo "Warning: Test report was not generated."
fi

echo "QE tests completed."

# If we started the server, it will be killed by the trap set earlier