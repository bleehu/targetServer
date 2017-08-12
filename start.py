import argparse #we use the argparse module for passing command-line arguments on startup.
from base64 import b64encode, b64decode
import csv #sometimes we save or read stuff in .csv format. This helps with that a lot.
#flask is a python webserver built on Werkzeug. This is what is in charge of our 
from flask import Flask, render_template, request, redirect, session, escape, flash
import json #sometimes we load or save things in json. This helps with that.
import pdb	#Python Debuger is what I use to fix borked code. It should not be called in production EVER!
#but it's very helpful when being run locally.

import os	#we need os to read and write files as well as to make our filepaths relative.
import logging #When we aren't running locally, we need the server to log what's happening so we can see any
#intrusions or help debug why it's breaking if it does so. This module handles that beautifully.
import xml.etree.ElementTree #Sometimes we write or read things in XML. This does that well.
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 # 1024 bytes x 1024 is a MB. Prevents people from uploading 40 GB pictures
app.config.from_object(__name__)
global log

""" we call this any time someone checks out a page on the site that should be off-limits to someone who
		hasn't logged in. If they aren't logged in, it returns false, if they are, it returns true."""
def check_auth(session):
	if 'username' not in session.keys():
		log.error("Anonymous attempt to access %s! user_agent:%s, remoteIP:%s" % (request.path, request.user_agent.string, request.remote_addr))
		return False
	blacklisted_UA = ['zgrab', 'vas']
	for ua in blacklisted_UA:
		if ua in request.user_agent.string.lower():
			return False
	return True

"""handles the display of the main page for the site. """
@app.route("/")	#tells flask what url to trigger this behavior for. In this case, the main page of the site.
def hello():			#tells flask what method to use when you hit a particular route. Same as regular python function definition.
	session['X-CSRF'] = "foxtrot"	#set a session token. This helps prevent session takeover hacks. 
	pc = None	#player character defaults to None if user isn't logged in.
	comments = []
	with open("comments.csv") as commentfile:
		csv_reader = csv.reader(commentfile, delimiter=',', quotechar='"')
		for line in csv_reader:
			comments.append(line)
	return render_template('index.html', session=session, comments=comments) #the flask method render_template() shows a jinja template 
	#jinja templates are kept in the /templates/ directory. Save them as .html files, but secretly, they use jinja to generate web pages
	#dynamically. 

@app.route("/comment", methods=['POST'])
def comment():
	form = request.form
	with open("comments.csv", 'a') as commentfile:
		csv_writer = csv.writer(commentfile, delimiter=',', quotechar='"')
		csv_writer.writerow([session['displayname'], form['comment']])
	return redirect("/")

def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", metavar="###.###.###.###", help="Your local IP address. use ifconfig on linux.")
	parser.add_argument("-p", metavar="Port number")
	args = parser.parse_args()
	return args
	
@app.route("/login", methods=['POST'])
def login():
	form = request.form
	uname = escape(form['uname'])
	passwerd = escape(form['password'])
	usernames = []
	user = None;
	with open("passwords.txt", 'rb') as passfile:
		for line in passfile:
			usernames.append(line.split(":"))
	for pair in usernames:
		if uname.strip() == pair[0]:
			if passwerd.strip() == pair[1].strip():
				user = uname.strip()
				
	
	if user != None:
		session['username'] = uname
		session['displayname'] = uname
		session['role'] = 'admin'
		log.info("%s logged in" % uname)
		flash('Logged in.')
	else:
		log.warn("%s failed to log in with password %s. user_agent:%s, remoteIP:%s" % (uname, passwerd, request.user_agent.string, request.remote_addr))
		flash('Failed to log in; username or password incorrect.')
	return redirect("/")

@app.route("/logout", methods=['POST'])
def logout():
	form = request.form
	if 'X-CSRF' in form.keys() and form['X-CSRF'] == session['X-CSRF']:
		log.info("%s logged out" % session['username'])
		session.pop('username', None)
		session.pop('character', None)
	return redirect("/")

@app.route("/npcgen", methods=['GET'])
def npcgen():
	return render_template("npcgen.html")

"""Most legitimate web scrapers check a text file in /robots.txt to see 
	where they should be allowed to look. This is how google, bing and bindu
	catalogue pages available to search. By default, we tell these robots to
	leave us alone."""
@app.route('/robots.txt')
def roblocker():
	return "User-agent: *\nDisallow: /"

""" set generic handlers for common errors."""
@app.errorhandler(500) #an HTTP 500 is given when there's a server error, for instance if  there's a Nonetype error in python. 
def borked_it(error):
	uname = "Anonymous"
	if 'username' in session.keys():
		uname = session['username']
	log.error("%s got a 500 looking for %s. User Agent: %s, remote IP: %s" % (uname, request.path, request.user_agent.string, request.remote_addr))
	return render_template("501.html", error=error)
	
@app.errorhandler(404) # an HTTP 404 Not Found happens if the user searches for a url which doesn't exist. like /fuzzyunicorns
def missed_it(error):
	uname = "Anonymous"
	if 'username' in session.keys():
		uname = session['username']
	log.warn("%s got a 404 looking for %s. User Agent: %s, remote IP: %s" % (uname, request.path, request.user_agent.string, request.remote_addr))
	return render_template("404.html", error=error)

if __name__ == "__main__":
	args = get_args()
	host = "localhost" #default to local only when running.
	if args.i:	# if given a -i ip.ip.ip.address, open that on LAN, so friends can visit your site.
		host = args.i
	local_dir = os.path.dirname(__file__) #get local directory, so we know where we are saving files.
	log_filename = os.path.join(local_dir,"cxDocs.log") #save a log of web traffic in case something goes wrong.
	logging.basicConfig(filename=log_filename, level=logging.INFO)
	global log
	log = logging.getLogger("cxDocs:")
	app.secret_key = '$En3K9lEj8GK!*v9VtqJ' #todo: generate this dynamically
	#app.config['SQLAlchemy_DATABASE_URI'] = 'postgresql://searcher:AllDatSQL@localhost/mydb'
	#app.config['SQLAlchemy_ECHO'] = True
	app.run(host = host, threaded=True, port=args.p)
	