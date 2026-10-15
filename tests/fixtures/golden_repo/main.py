def find_user(db, user_id):
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def summarize(items):
    return [item.name for item in items]
