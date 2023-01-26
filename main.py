import OpenSSL
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()
app.ssl_context = ('cert.pem', 'key.pem')


@app.middleware("http")
async def client_certificate_validation_middleware(request: Request, call_next):
    if 'ssl' not in request.client or not request.client.ssl:
        raise HTTPException(
            status_code=400, detail="Client certificate not found")
    cert = request.client.ssl.peercert
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
    if not x509.has_expired():
        raise HTTPException(
            status_code=400, detail="Client certificate has expired")
    await call_next(request)


@app.get("/home")
def index():
    return {"msg": "You are welcome"}
