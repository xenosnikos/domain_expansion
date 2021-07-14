from flask import Flask
from flask_restful import Api

from controllers.domain_expansion import DomainExpansion

app = Flask(__name__)
api = Api(app)

api.add_resource(DomainExpansion, "/v2/expansion")

if __name__ == "__main__":
    app.run()
