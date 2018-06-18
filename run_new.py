#!venv/bin/python
from logging import FileHandler, WARNING

# Adding 2 environment variables before importing app config.
import os

from flask import Flask, request, redirect, url_for, flash, jsonify, make_response
from werkzeug.utils import secure_filename

os.environ["SECRET_KEY"] = "curatus_temp_pw_key"
os.environ["APP_SETTINGS"] = "project.server.config.ProductionConfig"

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

from manage import app

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

from os import listdir

import ocr

#!/usr/bin/env python
from stat import S_ISREG, ST_CTIME, ST_MODE
import os, sys, time
def latest_file(path = ""):
	# path to the directory (relative or absolute)
	dirpath = sys.argv[1] if len(sys.argv) == 2 else r'.'+path
	print(dirpath)
	# get all entries in the directory w/ stats
	entries = (os.path.join(dirpath, fn) for fn in os.listdir(dirpath))
	entries = ((os.stat(path), path) for path in entries)

	# leave only regular files, insert creation date
	entries = ((stat[ST_CTIME], path)
	           for stat, path in entries if S_ISREG(stat[ST_MODE]))
	#NOTE: on Windows `ST_CTIME` is a creation date 
	#  but on Unix it could be something else
	#NOTE: use `ST_MTIME` to sort by a modification date
	paths_in_ascending_time_order=[]
        for (date,path) in sorted(entries):
            paths_in_ascending_time_order.append(path.split("uploads/")[1])
	return paths_in_ascending_time_order
	return sorted(entries)[-1][1].split("uploads/")[1]




def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            file_list = listdir('./uploads')
	    print("latest_file_path: " + str(latest_file(path="/uploads")[-1]))
            text_output = ocr.ocr("http://ec2-52-23-186-226.compute-1.amazonaws.com:8084/"+latest_file(path="/uploads")[-1])
            #text_output = ocr.ocr("http://ec2-52-23-186-226.compute-1.amazonaws.com:8084/"+latest_file(path ="/uploads"))
            return make_response(jsonify({'file_list':file_list, 'text_output' : text_output})), 201
            return redirect(url_for('uploaded_file', filename=filename)), 201
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <p><input type=file name=file>
         <input type=submit value=Upload>
    </form>
    '''
from flask import send_from_directory

@app.route('/uploads/<filename>',methods=['GET','POST'])
def uploaded_file(filename):
    print(str(url_for('uploaded_file',filename=filename)))
    return send_from_directory('./uploads',filename)

file_handler = FileHandler('./project/logs/error_log.txt')
file_handler.setLevel(WARNING)

print(app.config.get('SECRET_KEY'))

app.logger.addHandler(file_handler)
app.run(debug=False,host='0.0.0.0',port=5000)
