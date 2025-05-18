"Demo Flask application"
import json
import os
import subprocess
import requests
import secrets
import smtplib
from email.mime.text import MIMEText
from flask import session

from flask import Flask, render_template, render_template_string, url_for, redirect, flash, g, session, request, jsonify
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, HiddenField, validators
import boto3

import config
import util

def get_instance_document():
    try:
        r = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document")
        if r.status_code == 401:
            token=(
                requests.put(
                    "http://169.254.169.254/latest/api/token", 
                    headers={'X-aws-ec2-metadata-token-ttl-seconds': '21600'}, 
                    verify=False, timeout=1
                )
            ).text
            r = requests.get(
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                headers={'X-aws-ec2-metadata-token': token}, timeout=1
            )
        r.raise_for_status()
        return r.json()
    except:
        print(" * Instance metadata not available")
        return { "availabilityZone" : "us-fake-1a",  "instanceId" : "i-fakeabc" }

if "DYNAMO_MODE" in os.environ:
    import database_dynamo as database
else:
    import database

application = Flask(__name__)
application.secret_key = config.FLASK_SECRET

doc = get_instance_document()
availablity_zone = doc["availabilityZone"]
instance_id = doc["instanceId"]

badges = {
    "apple" : "Mac User",
    "windows" : "Windows User",
    "linux" : "Linux User",
    "video-camera" : "Digital Content Star",
    "trophy" : "Employee of the Month",
    "camera" : "Photographer",
    "plane" : "Frequent Flier",
    "paperclip" : "Paperclip Afficionado",
    "coffee" : "Coffee Snob",
    "gamepad" : "Gamer",
    "bug" : "Bugfixer",
    "umbrella" : "Seattle Fan",
}

### FlaskForm set up
class EmployeeForm(FlaskForm):
    """flask_wtf form class"""
    employee_id = HiddenField()
    photo = FileField('image')
    full_name = StringField(u'Full Name', [validators.InputRequired()])
    location = StringField(u'Location', [validators.InputRequired()])
    job_title = StringField(u'Job Title', [validators.InputRequired()])
    badges = HiddenField(u'Badges')

@application.before_request
def before_request():
    "Set up globals referenced in jinja templates"
    g.availablity_zone = availablity_zone
    g.instance_id = instance_id

@application.route("/")
def home():
    # if 'user' in session:
    #     return redirect(url_for('dashboard'))
    return render_template("main.html")

@application.route("/add")
def add():
    "Add an employee"
    form = EmployeeForm()
    return render_template("view-edit.html", form=form, badges=badges)

@application.route("/edit/<employee_id>")
def edit(employee_id):
    "Edit an employee"
    s3_client = boto3.client('s3')
    employee = database.load_employee(employee_id)
    signed_url = None
    if "object_key" in employee and employee["object_key"]:
        signed_url = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': config.PHOTOS_BUCKET, 'Key': employee["object_key"]}
        )

    form = EmployeeForm()
    form.employee_id.data = employee['id']
    form.full_name.data = employee['full_name']
    form.location.data = employee['location']
    form.job_title.data = employee['job_title']
    if 'badges' in employee:
        form.badges.data = employee['badges']

    return render_template("view-edit.html", form=form, badges=badges, signed_url=signed_url)

@application.route("/save", methods=['POST'])
def save():
    "Save an employee"
    form = EmployeeForm()
    s3_client = boto3.client('s3')
    key = None
    if form.validate_on_submit():
        if form.photo.data:
            image_bytes = util.resize_image(form.photo.data, (120, 160))
            if image_bytes:
                try:
                    # save the image to s3
                    prefix = "employee_pic/"
                    key = prefix + util.random_hex_bytes(8) + '.png'
                    s3_client.put_object(
                        Bucket=config.PHOTOS_BUCKET,
                        Key=key,
                        Body=image_bytes,
                        ContentType='image/png'
                    )
                except:
                    pass
        
        if form.employee_id.data:
            database.update_employee(
                form.employee_id.data,
                key,
                form.full_name.data,
                form.location.data,
                form.job_title.data,
                form.badges.data)
        else:
            database.add_employee(
                key,
                form.full_name.data,
                form.location.data,
                form.job_title.data,
                form.badges.data)
        flash("Saved!")
        return redirect(url_for("home"))
    else:
        return "Form failed validate"

@application.route("/employee/<employee_id>")
def view(employee_id):
    "View an employee"
    s3_client = boto3.client('s3')
    employee = database.load_employee(employee_id)
    if "object_key" in employee and employee["object_key"]:
        try:
            employee["signed_url"] = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': config.PHOTOS_BUCKET, 'Key': employee["object_key"]}
            )
        except:
            pass
    form = EmployeeForm()

    return render_template_string("""
        {% extends "main.html" %}
        {% block head %}
            {{employee.full_name}}
            <a class="btn btn-primary float-right" href="{{ url_for("edit", employee_id=employee.id) }}">Edit</a>
            <a class="btn btn-primary float-right" href="{{ url_for('home') }}">Home</a>
        {% endblock %}
        {% block body %}

  <div class="row">
    <div class="col-md-4">
        {% if employee.signed_url %}
        <img alt="Mugshot" src="{{ employee.signed_url }}" />
        {% endif %}
    </div>

    <div class="col-md-8">
      <div class="form-group row">
        <label class="col-sm-2">{{form.location.label}}</label>
        <div class="col-sm-10">
        {{employee.location}}
        </div>
      </div>
      <div class="form-group row">
        <label class="col-sm-2">{{form.job_title.label}}</label>
        <div class="col-sm-10">
        {{employee.job_title}}
        </div>
      </div>
      {% for badge in badges %}
      <div class="form-check">
        {% if badge in employee['badges'] %}
        <span class="badge badge-primary"><i class="fa fa-{{badge}}"></i> {{badges[badge]}}</span>
        {% endif %}
      </div>
      {% endfor %}
      &nbsp;
    </div>
  </div>
</form>
        {% endblock %}
    """, form=form, employee=employee, badges=badges)

@application.route("/delete/<employee_id>")
def delete(employee_id):
    "delete employee route"
    database.delete_employee(employee_id)
    flash("Deleted!")
    return redirect(url_for("home"))

@application.route("/info")
def info():
    "Webserver info route"
    return render_template_string("""
            {% extends "main.html" %}
            {% block head %}
                Instance Info
            {% endblock %}
            {% block body %}
            <b>instance_id</b>: {{g.instance_id}} <br/>
            <b>availability_zone</b>: {{g.availablity_zone}} <br/>
            <hr/>
            <small>Stress cpu:
            <a href="{{ url_for('stress', seconds=60) }}">1 min</a>,
            <a href="{{ url_for('stress', seconds=300) }}">5 min</a>,
            <a href="{{ url_for('stress', seconds=600) }}">10 min</a>
            </small>
            {% endblock %}""")

@application.route("/info/stress_cpu/<seconds>")
def stress(seconds):
    "Max out the CPU"
    flash("Stressing CPU")
    subprocess.Popen(["stress", "--cpu", "8", "--timeout", seconds])
    return redirect(url_for("info"))

from forms import RegisterForm, LoginForm
import user_dynamo

@application.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        user = user_dynamo.get_user(form.username.data)
        if user and user['password'] == user_dynamo.hash_password(form.password.data):
            session['user'] = form.username.data
            session['role'] = user.get('role', 'user')  # Save role in session
            print("Logged in user:", session.get('user'), "Role:", session.get('role'))
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password."
    return render_template('login_email.html', form=form, error=error)

@application.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('home'))

@application.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@application.route('/about')
def about():
    return "About page coming soon!"

@application.route('/contact')
def contact():
    return "Contact page coming soon!"

@application.route("/directory")
def directory():
    s3_client = boto3.client('s3')
    employees = database.list_employees()
    if employees == 0:
        return render_template_string("""        
        {% extends "main.html" %}
        {% block head %}
        Employee Directory - Home
        <a class="btn btn-primary float-right" href="{{ url_for('add') }}">Add</a>
        {% endblock %}
        {% block body %}
        <h4>Empty Directory</h4>
        {% endblock %}
        """)
    else:
        for employee in employees:
            try:
                if "object_key" in employee and employee["object_key"]:
                    employee["signed_url"] = s3_client.generate_presigned_url(
                        'get_object',
                        Params={'Bucket': config.PHOTOS_BUCKET, 'Key': employee["object_key"]}
                    )
            except: 
                pass

    return render_template_string("""
        {% extends "main.html" %}
        {% block head %}
        Employee Directory - Home
        <a class="btn btn-primary float-right" href="{{ url_for('add') }}">Add</a>
        {% endblock %}
        {% block body %}
            {%  if not employees %}<h4>Empty Directory</h4>{% endif %}

            <table class="table table-bordered">
              <tbody>
            {% for employee in employees %}
                <tr>
                  <td width="100">{% if employee.signed_url %}
                  <img width="50" src="{{employee.signed_url}}" /><br/>
                  {% endif %}
                  <a href="{{ url_for('delete', employee_id=employee.id) }}"><span class="fa fa-remove" aria-hidden="true"></span> delete</a>
                  </td>
                  <td>
                    <a href="{{ url_for('edit', employee_id=employee.id) }}">{{employee.full_name}}</a>
                    {% for badge in badges %}
                    {% if badge in employee['badges'] %}
                    <i class="fa fa-{{badge}}" title="{{badges[badge]}}"></i>
                    {% endif %}
                    {% endfor %}
                    <br/>
                    <small>{{employee.location}}</small>
                  </td>
                </tr>
            {% endfor %}
              </tbody>
            </table>
        {% endblock %}
    """, employees=employees, badges=badges)
    
@application.route('/register', methods=['GET'])
def register_form():
    return render_template('register.html')

def check_hr_code(hrcode):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('HRCode')
    response = table.get_item(Key={'code': hrcode})
    return response.get('Item')

@application.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    hrcode = data.get('hrcode')

    hr_code_item = check_hr_code(hrcode)
    if not hr_code_item:
        return jsonify({'success': False, 'error': 'Invalid HR code.'})

    if user_dynamo.get_user(email):
        return jsonify({'success': False, 'error': 'Email already registered.'})

    role = hr_code_item.get('role', 'user')
    user_dynamo.add_user(email, password, name=name, hrcode=hrcode, role=role)
    return jsonify({'success': True})

@application.route('/check_email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email')
    user = user_dynamo.get_user(email)
    return jsonify({'exists': bool(user)})

from functools import wraps
from flask import session, redirect, url_for, flash

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or (session['role'] != role and session['role'] != 'root'):
                flash("You do not have permission to access this page.")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Now you can use @role_required('hr') below this line

@application.route('/hr/generate_hr_code', methods=['GET', 'POST'])
@role_required('hr')
def generate_hr_code():
    if request.method == 'GET':
        return render_template('add-employee.html')
    data = request.get_json()
    email = data.get('email')
    role = data.get('role', 'user')
    if not email:
        return jsonify({'success': False, 'error': 'Email is required'})
    code = secrets.token_hex(4)
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('HRCode')
    table.put_item(Item={
        'code': code,
        'email': email,
        'role': role
    })
    return jsonify({'success': True, 'code': code})


