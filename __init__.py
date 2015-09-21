from flask import Flask, request, jsonify, render_template
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import desc
import datetime
import re
import socket
import urllib2

app = Flask(__name__)
db = SQLAlchemy(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/email_header'
db.init_app(app)

class Header(db.Model):
  __tablename__  = 'header'
  header_id 	 = db.Column(db.Integer, primary_key = True)
  submit_ip 	 = db.Column(db.String(100))
  header_content = db.Column(db.Text)
  sender_ip 	 = db.Column(db.String(100))
  sender_host    = db.Column(db.String(100))
  sender_abuse   = db.Column(db.String(100))
  dkim_pass 	 = db.Column(db.Boolean)
  spf_pass  	 = db.Column(db.Boolean)
  is_blacklisted = db.Column(db.Boolean)
  created_at 	 = db.Column(db.DateTime)
  return_path 	 = db.Column(db.String(100))
  dmarc_pass     = db.Column(db.Boolean)

@app.route('/', methods=['GET'])
def index():
  return render_template('index.html')

@app.route('/about/', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/api/', methods=['GET'])
def api():
    return render_template('apidocs.html')

@app.route('/submit/', methods=['GET', 'POST'])
def submit():
	if request.method == 'GET':
		return render_template('form.html')
	if request.method == 'POST':
		post_data = request.form['header_content']
		ips 	  	 = get_sender_ip(post_data)
		hosts 	  	 = get_sender_host(ips)
		pos 	  	 = next(i for i, j in enumerate(hosts) if j)
		sender_abuse = get_sender_abuse(hosts[pos])
		spf_pass 	 = get_spf(post_data)
		dkim_pass 	 = get_dkim(post_data)
		dmarc_pass	 = get_dmarc(post_data)
		created_at 	 = get_created_at()
		return_path  = get_return_path(post_data)
		header 		 = Header(submit_ip = request.environ['REMOTE_ADDR'], header_content = post_data, sender_ip = ips[pos], sender_host = hosts[pos], sender_abuse = sender_abuse, spf_pass = spf_pass, dkim_pass = dkim_pass, dmarc_pass = dmarc_pass, created_at = created_at, return_path = return_path)
	  	
	  	db.session.add(header)
	  	db.session.commit()
	  	return render_template('results.html', sender_abuse=sender_abuse, sender_host=hosts[pos], sender_ip=ips[pos], return_path=return_path)


@app.route('/api/1.0/reports/', methods=['GET','POST'])
def apireports():
	if request.method == 'GET':
	  lim = request.args.get('limit', 10)
	  off = request.args.get('offset', 0)

	  results = Header.query.order_by(desc('created_at')).limit(lim).offset(off).all()

	  json_results = []

	  for result in results:
	    header = {
	      'header_id': result.header_id,
	      'sender_ip': result.sender_ip,
	      'sender_host': result.sender_host,
	      'sender_abuse': result.sender_abuse,
	      'dkim_pass': result.dkim_pass,
	      'spf_pass': result.spf_pass,
	      'dmarc_pass': result.dmarc_pass,
	      'created_at': result.created_at,
	      'return_path': result.return_path
	    }
	    
	    json_results.append(header)

	  return jsonify(items=json_results)
	if request.method == 'POST':
		post_data 	 = request.data
		ips 	  	 = get_sender_ip(post_data)
		hosts 	  	 = get_sender_host(ips)
		pos 	  	 = next(i for i, j in enumerate(hosts) if j)
		sender_abuse = get_sender_abuse(hosts[pos])
		spf_pass 	 = get_spf(post_data)
		dkim_pass 	 = get_dkim(post_data)
		dmarc_pass	 = get_dmarc(post_data)
		created_at 	 = get_created_at()
		return_path  = get_return_path(post_data)
		header 		 = Header(submit_ip = request.environ['REMOTE_ADDR'], header_content = post_data, sender_ip = ips[pos], sender_host = hosts[pos], sender_abuse = sender_abuse, spf_pass = spf_pass, dkim_pass = dkim_pass, dmarc_pass = dmarc_pass, created_at = created_at, return_path = return_path)
	  	
	  	db.session.add(header)
	  	db.session.commit()
	  	return jsonify(header_id = header.header_id, sender_ip = ips[pos], sender_host = hosts[pos], sender_abuse = sender_abuse, spf_pass = spf_pass, dkim_pass = dkim_pass, dmarc_pass = dmarc_pass, created_at = created_at, return_path = return_path)



@app.route('/api/1.0/reports/<int:header>/', methods=['GET'])
def apireport(header):
	result = Header.query.get(header)
	header = {
		'header_id': result.header_id,
		'sender_ip': result.sender_ip,
		'sender_host': result.sender_host,
		'sender_abuse': result.sender_abuse,
		'dkim_pass': result.dkim_pass,
		'spf_pass': result.spf_pass,
		'dmarc_pass': result.dmarc_pass,
		'created_at': result.created_at,
		'return_path': result.return_path
	}

	return jsonify(header)


def get_sender_ip(content):
	ip_array = []
	get_ips = re.findall("(?<![\d.])0*(1\d\d|2[0-4]\d|25[0-5]|[1-9]?\d)\.0*([1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.0*(1\d\d|2[0-4]\d|25[0-5]|[1-9]?\d)\.0*(1\d\d|2[0-4]\d|25[0-5]|[1-9]?\d)", content)
	for ips in get_ips:
		ip = '.'.join(ips)
		if ip not in ip_array:
			ip_array.append(ip)
	return ip_array

def get_submit_ip():
	return True

def get_sender_host(ips):
	hosts = []
	for ip in ips:
		try:
			host = socket.gethostbyaddr(ip)
			if host not in hosts:
				hosts.append(host[0])
		except:
			host = None
			hosts.append(host)
	return hosts


def get_sender_abuse(sender_host):
	abuse_content = urllib2.urlopen("http://abuse.net/lookup.phtml?domain=%s" % sender_host).read()
	regex = re.compile('([\w\-\.]+@(\w[\w\-]+\.)+[\w\-]+)')
	abuse_email = regex.findall(abuse_content)
	return abuse_email[0][0]


def get_dkim(content):
	if re.findall('dkim=pass', content):
		return True
	else:
		return False

def get_spf(content):
	if re.findall('spf=pass', content):
		return True
	else:
		return False

def get_dmarc(content):
	if re.findall('dmarc=pass', content):
		return True
	else:
		return False

def get_blacklisted(ips):
	return False

def get_created_at():
	return datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')

def get_return_path(content):
	return_path = re.findall('(Return-Path: [\S]+)', content)
	for email in return_path:
		email = email.replace('Return-Path: ','')
		email = email.replace('<','')
		email = email.replace('>','')
		email = email.strip()
		return email


if __name__ == '__main__':
  app.run(debug=True)
