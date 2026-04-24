# node:22-alpine: minimal image; pinned to major version for reproducibility
FROM node:22-alpine

WORKDIR /app

# Copy all source files (fixtures included for self-contained testing)
COPY . /app

# No npm install: scanner uses only Node.js built-in modules (fs, path)

# Run the scanner against the bundled fixture directory to demonstrate it works
CMD ["node", "scanner.js", "/app/fixtures", "--out", "/tmp/scan-results"]
