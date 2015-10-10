from main import db

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String())
    accessToken = db.Column(db.String())
    accessTokenSecret = db.Column(db.String())
    accessHash = db.Column(db.String())

    def __init__(self, username, accessToken, accessTokenSecret, accessHash):
        self.username = username
        self.accessToken = accessToken
        self.accessTokenSecret = accessTokenSecret
        self.accessHash = accessHash

    def __repr__(self):
        return '<User {}>'.format(self.username)

    @staticmethod
    def get_by_access_hash(accessHash):
        return User.query.filter_by(accessHash=accessHash).first()
