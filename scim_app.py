from fastapi import FastAPI, Request, Header, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import uvicorn, uuid, os, json
from pathlib import Path
from config import Config
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Ensure storage exists
Config.DATA_DIR.mkdir(exist_ok=True)
USERS_FILE = Config.USERS_FILE
GROUPS_FILE = Config.GROUPS_FILE

def load_json(path):
    return json.loads(path.read_text()) if path.exists() else {}

def save_json(path, data):
    path.write_text(json.dumps(data, indent=2))

users = load_json(USERS_FILE)
groups = load_json(GROUPS_FILE)

def verify_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]
    if token != Config.SCIM_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid bearer token")

# SCIM CRUD
@app.get("/scim/v2/Users", dependencies=[Depends(verify_token)])
async def list_users():
    return {"Resources": list(users.values()), "totalResults": len(users)}

@app.post("/scim/v2/Users", dependencies=[Depends(verify_token)])
async def create_user(request: Request):
    data = await request.json()
    user_id = str(uuid.uuid4())
    data["id"] = user_id
    users[user_id] = data
    save_json(USERS_FILE, users)
    return JSONResponse(status_code=201, content=data)

@app.delete("/scim/v2/Users/{user_id}", dependencies=[Depends(verify_token)])
async def delete_user(user_id: str):
    users.pop(user_id, None)
    save_json(USERS_FILE, users)
    return {"status": "deleted"}

@app.get("/scim/v2/Groups", dependencies=[Depends(verify_token)])
async def list_groups():
    return {"Resources": list(groups.values()), "totalResults": len(groups)}

@app.post("/scim/v2/Groups", dependencies=[Depends(verify_token)])
async def create_group(request: Request):
    data = await request.json()
    group_id = str(uuid.uuid4())
    data["id"] = group_id
    groups[group_id] = data
    save_json(GROUPS_FILE, groups)
    return JSONResponse(status_code=201, content=data)

# Web UI
@app.get("/ui/users", response_class=HTMLResponse)
async def ui_users(request: Request):
    return templates.TemplateResponse("users.html", {"request": request, "users": users})

@app.get("/ui/groups", response_class=HTMLResponse)
async def ui_groups(request: Request):
    return templates.TemplateResponse("groups.html", {"request": request, "groups": groups})

if __name__ == "__main__":
    uvicorn.run("scim_app:app", host=Config.HOST, port=Config.PORT, reload=Config.DEBUG)
