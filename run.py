#!venv/bin/python
from logging import FileHandler, WARNING
from manage import app

file_handler = FileHandler('./project/logs/error_log.txt')
file_handler.setLevel(WARNING)

app.logger.addHandler(file_handler)
app.run(debug=False,host='0.0.0.0',port=5000)
