# This is the main FastAPI application file that contains the API endpoints and the main logic for the application.
# The application includes the following features:
# - JWT token-based authentication
# - MongoDB and MariaDB connections
# - NLP processing using spaCy
# - API endpoints for querying MongoDB and MariaDB
# - A combined endpoint that aggregates data from MongoDB and MariaDB
# - A dialogue endpoint that uses NLP to search both MongoDB collections
# - A token endpoint for generating JWT tokens
# - A simple endpoint to get MongoDB data (protected)
# - A combined endpoint that aggregates MongoDB and SQL data
# To run the application, use the following command:
# uvicorn app_api:app --reload
# This will start the FastAPI application on http://localhost:8000.
# You can test the endpoints using tools like Postman or cURL.
# For the dialogue endpoint, you can send a POST request to http://localhost:8000/dialogue with a JSON body containing the query field.
# For example:
# {
#     "query": "Show me the data for CWE-79"
# }
# This will return a JSON response with the processed query and the data from both MongoDB collections.
# The application also includes a token endpoint for generating JWT tokens. You can use this token to authenticate requests to protected endpoints.
# For example, you can use the token to access the /mongo/items endpoint, which returns data from the MongoDB collection.
# To get a token, send a POST request to http://localhost:8000/token with the username and password in the request body.
# For example:
# {
#     "username": "testuser",
#     "password": "testpassword"
# }
# This will return a JSON response with the access token. You can use this token in the Authorization header to access protected endpoints.
# The application also includes an endpoint to get data from the SQL database. You can access this endpoint at http://localhost:8000/sql/domains.
# This endpoint retrieves data from the domains table in the MariaDB database and returns it as a JSON response.
# The combined endpoint aggregates data from both MongoDB and MariaDB. You can access this endpoint at http://localhost:8000/combined.
# This endpoint returns a JSON response with data from the MongoDB collection and the SQL database.
# The application demonstrates how to build a FastAPI application with multiple endpoints, database connections, and token-based authentication.
# It also shows how to use NLP processing to enhance search capabilities in the application.
# This application can be extended further to include additional features and endpoints based on the requirements of the project.
# ---------------------------
# Import Required Libraries
# ---------------------------
import os
import asyncio
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from bson import ObjectId
import mariadb
import spacy
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()
# ---------------------------
# FastAPI App Initialization
app = FastAPI()

# ---------------------------
# Security Settings: JWT Token
# ---------------------------
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# ---------------------------
# Security Settings: JWT Token
# ---------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
         status_code=401,
         detail="Could not validate credentials",
         headers={"WWW-Authenticate": "Bearer"},
    )
    try:
         payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
         username: str = payload.get("sub")
         if username is None:
              raise credentials_exception
         return {"username": username}
    except JWTError:
         raise credentials_exception

@app.post("/token", response_model=dict)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # For demonstration, we use static credentials
    if form_data.username != "testuser" or form_data.password != "testpassword":
         raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": form_data.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# ---------------------------
# MongoDB Setup (Motor)
# ---------------------------
mongo_client = AsyncIOMotorClient(os.getenv("MONGO_URI"))
mongo_db = mongo_client[os.getenv("MONGO_DB")]
collection_vuln = mongo_db[os.getenv("MONGODB_COLLECTION_B1_0")]
collection_virustotal = mongo_db[os.getenv("MONGODB_COLLECTION_B1_1")]

def serialize_document(doc: dict) -> dict:
    doc["id"] = str(doc["_id"])
    del doc["_id"]
    return doc

# ---------------------------
# SQL Database Endpoint using MariaDB Connector (synchronous, run in a thread)
# ---------------------------
def query_sql_domains() -> list:
    try:
        conn = mariadb.connect(
            user=os.getenv("USER_MARIADB"),
            password=os.getenv("PASSWORD_MARIADB"),
            host=os.getenv("HOST_MARIADB"),
            port=int(os.getenv("PORT_MARIADB")),
            database=os.getenv("DATABASE_MARIADB")
        )
    except mariadb.Error as e:
        raise Exception(f"Error connecting to MariaDB: {e}")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM domains")
    rows = cursor.fetchall()
    data = []
    for row in rows:
        data.append({
            "id": row[0],
            "domain": row[1],
            "status": row[2],
            "threat": row[3]
        })
    conn.close()
    return data

@app.get("/sql/domains", response_model=list)
async def get_sql_domains(current_user: dict = Depends(get_current_user)):
    try:
        data = await asyncio.to_thread(query_sql_domains)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------
# NLP Helper Function (using spaCy)
# ---------------------------
nlp = spacy.load("en_core_web_sm")

def process_query(query: str) -> str:
    doc = nlp(query)
    keywords = [token.lemma_ for token in doc if token.pos_ in ("NOUN", "PROPN", "ADJ")]
    return " ".join(keywords)

# ---------------------------
# Dialogue Endpoint (using NLP to search both MongoDB collections)
# ---------------------------
class DialogueRequest(BaseModel):
    query: str

@app.post("/dialogue", response_model=dict)
async def dialogue_endpoint(dialogue: DialogueRequest, current_user: dict = Depends(get_current_user)):
    try:
        query = dialogue.query
        processed_query = process_query(query)
        regex_pattern = processed_query if processed_query else query

        vuln_items = await collection_vuln.find({"cwe_id": {"$regex": regex_pattern, "$options": "i"}}).to_list(100)
        vt_items = await collection_virustotal.find({"id": {"$regex": regex_pattern, "$options": "i"}}).to_list(100)

        response_text = (
             f"I refined your query to: '{processed_query}'. "
             f"I found {len(vuln_items)} entries in vulnerability data and {len(vt_items)} in Virustotal data."
        )

        lower_query = query.lower()
        if ("give me the data" in lower_query or "show data" in lower_query or "list data" in lower_query):
             vuln_data = [serialize_document(item) for item in vuln_items[:5]]
             vt_data = [serialize_document(item) for item in vt_items[:5]]
             return {"response": response_text, "processed_query": processed_query, "data": {"vuln_cwe": vuln_data, "virustotal": vt_data}}
        return {"response": response_text, "processed_query": processed_query}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

# ---------------------------
# Simple Endpoint to Get MongoDB Data (Protected)
# ---------------------------
@app.get("/mongo/items", response_model=list)
async def get_mongo_items(current_user: dict = Depends(get_current_user)):
    items = await collection_vuln.find().to_list(100)
    return [serialize_document(item) for item in items]

# ---------------------------
# Combined Endpoint (aggregates MongoDB and SQL data)
# ---------------------------
@app.get("/combined", response_model=dict)
async def combined_endpoint(current_user: dict = Depends(get_current_user)):
    mongo_items = await collection_vuln.find().to_list(100)
    sql_data = await asyncio.to_thread(query_sql_domains)
    return {
         "mongo_vuln_items": [serialize_document(item) for item in mongo_items],
         "sql_domains": sql_data
    }

# ---------------------------
# Run the App
# ---------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app_api:app", host="0.0.0.0", port=8000, reload=True)


