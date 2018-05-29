#!venv/bin/python
from logging import FileHandler, WARNING

# Adding 2 environment variables before importing app config.
import os
os.environ["SECRET_KEY"] = "curatus_temp_pw_key"
os.environ["APP_SETTINGS"] = "project.server.config.ProductionConfig"


from manage import app

file_handler = FileHandler('./project/logs/error_log.txt')
file_handler.setLevel(WARNING)

print(app.config.get('SECRET_KEY'))

app.logger.addHandler(file_handler)
app.run(debug=False,host='0.0.0.0',port=5000)
