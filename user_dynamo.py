import boto3
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(email, password, name=None, hrcode=None, role="user"):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    table.put_item(Item={
        'username': email,  # Use 'username' as the partition key
        'password': hash_password(password),
        'name': name,
        'hrcode': hrcode,
        'role': role
    })

def get_user(username):
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('Users')
    resp = table.get_item(Key={'username': username})
    return resp.get('Item')