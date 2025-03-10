from fastapi import FastAPI, HTTPException
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from bson import ObjectId
import os

app = FastAPI()

# MongoDB Atlas Connection (ensure MONGO_URI is set in your environment)
MONGO_URI = os.getenv("MONGO_URI")
client = AsyncIOMotorClient(MONGO_URI)
db = client["hacking_project"]

# Collections
collection = db["vuln_cwe"]
collection2 = db["virustotal_domains"]

# Pydantic model for first collection
class Item(BaseModel):
    name: str
    description: str

# Pydantic model for virustotal items
class VirustotalItem(BaseModel):
    domain: str
    detected: str
    positives: int
    total: int
    scan_date: str
    permalink: str

# Helper function for serializing MongoDB documents
def serialize_document(doc):
    doc["id"] = str(doc["_id"])
    del doc["_id"]
    return doc

# -------------------------
# Endpoints for first collection
# -------------------------
@app.post("/items/", response_model=dict)
async def create_item(item: Item):
    new_item = await collection.insert_one(item.dict())
    return {"id": str(new_item.inserted_id)}

@app.get("/items/")
async def get_items():
    items = await collection.find().to_list(100)
    return [serialize_document(item) for item in items]

@app.get("/items/{item_id}")
async def get_item(item_id: str):
    item = await collection.find_one({"_id": ObjectId(item_id)})
    if item:
        return serialize_document(item)
    raise HTTPException(status_code=404, detail="Item not found")

@app.put("/items/{item_id}")
async def update_item(item_id: str, item: Item):
    result = await collection.update_one({"_id": ObjectId(item_id)}, {"$set": item.dict()})
    if result.modified_count:
        return {"message": "Item updated"}
    raise HTTPException(status_code=404, detail="Item not found")

@app.delete("/items/{item_id}")
async def delete_item(item_id: str):
    result = await collection.delete_one({"_id": ObjectId(item_id)})
    if result.deleted_count:
        return {"message": "Item deleted"}
    raise HTTPException(status_code=404, detail="Item not found")

# -------------------------
# Endpoints for virustotal_domains (second collection)
# -------------------------
@app.post("/virustotal/", response_model=dict)
async def create_virustotal_item(item: VirustotalItem):
    new_item = await collection2.insert_one(item.dict())
    return {"id": str(new_item.inserted_id)}

@app.get("/virustotal/")
async def get_virustotal_items():
    items = await collection2.find().to_list(100)
    return [serialize_document(item) for item in items]

@app.get("/virustotal/{item_id}")
async def get_virustotal_item(item_id: str):
    item = await collection2.find_one({"_id": ObjectId(item_id)})
    if item:
        return serialize_document(item)
    raise HTTPException(status_code=404, detail="Virustotal item not found")

@app.put("/virustotal/{item_id}")
async def update_virustotal_item(item_id: str, item: VirustotalItem):
    result = await collection2.update_one({"_id": ObjectId(item_id)}, {"$set": item.dict()})
    if result.modified_count:
        return {"message": "Virustotal item updated"}
    raise HTTPException(status_code=404, detail="Virustotal item not found")

@app.delete("/virustotal/{item_id}")
async def delete_virustotal_item(item_id: str):
    result = await collection2.delete_one({"_id": ObjectId(item_id)})
    if result.deleted_count:
        return {"message": "Virustotal item deleted"}
    raise HTTPException(status_code=404, detail="Virustotal item not found")

# Run with: uvicorn main:app --reload

