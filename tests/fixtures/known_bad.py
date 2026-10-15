api_key = "Abcdefghijklmnopqrstuvwxyz123456"
key_data = "-----BEGIN PRIVATE KEY-----"
class Request:
    args = {"id": "x"}

class Database:
    def execute(self, query):
        return query

request = Request()
db = Database()
db.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")
cors_config = dict(origin="*")
DEBUG = True
# TODO finish the endpoint
def placeholder():
    pass

def load_items(items, db):
    for item in items:
        db.execute("SELECT * FROM items WHERE id = %s" % item.id)
