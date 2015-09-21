from flask import Flask, request, jsonify
from flask.ext.sqlalchemy import SQLAlchemy

@app.route('/', methods=['GET'])
def index():
  return render_template('index.html')

@app.route('/about', methods=['GET'])
def about():

class Header(db.Model):
  __tablename__ = 'header'
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
   
  def __init__(self, submit_ip, header_content, sender_ip, sender_host, sender_abuse, dkim_pass, spf_pass, is_blacklisted):
    self.submit_ip 		= submit_ip
    self.header_content = header_content
    self.sender_ip 		= sender_ip
    self.sender_host 	= sender_host
    self.sender_abuse 	= sender_abuse
    self.dkim_pass		= dkim_pass
    self.spf_pass		= spf_pass
    self.is_blacklisted	= is_blacklisted
    
@app.route('/api/1.0/reports/', methods=['GET','POST'])
def apireports():
    if request.method == 'GET':
      lim = request.args.get('limit', 10)
      off = request.args.get('offset', 0)

      results = Header.query.limit(lim).offset(off).all()

      json_results = []

      for result in results:
        header = {
          'header_id': result.header_id,
          'sender_ip': result.sender_ip,
          'sender_host': result.sender_host,
          'sender_abuse': result.sender_abuse,
          'dkim_pass': result.dkim_pass,
          'spf_pass': result.spf_pass,
          'created_at': result.created_at
        }
        
        json_results[] = header

      return jsonify(items=json_results)

@app.route('/api/1.0/reports/<int:header_id>', methods=['GET'])
def apireport():

