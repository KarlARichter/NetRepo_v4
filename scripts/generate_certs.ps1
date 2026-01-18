New-Item -ItemType Directory -Force -Path "certs" | Out-Null
# Requires OpenSSL installed and available on PATH.
openssl req -x509 -newkey rsa:2048 -nodes `
  -keyout certs/server.key `
  -out certs/server.crt `
  -days 365 `
  -subj "/CN=localhost"
Write-Host "Generated certs/server.crt and certs/server.key"
