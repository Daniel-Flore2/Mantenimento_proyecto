# app.py
from flask import Flask
from controller.controllerUser import app1_bp
from controller.controllerSniffer import app2_bp
from controller.controllerUserMaster import app3_bp


app = Flask(__name__)
app.register_blueprint(app1_bp)
app.register_blueprint(app2_bp)
app.register_blueprint(app3_bp)

if __name__ == '__main__':
    app.run(port=5000)
