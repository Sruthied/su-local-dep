from dotenv import load_dotenv
from os import getenv
from pymongo import MongoClient

load_dotenv()

client = MongoClient(getenv("MONGO_URI"))
db_client = client.Shootup
