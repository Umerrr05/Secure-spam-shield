from flask import Flask, redirect, render_template, request, jsonify,flash
from main import spam_detector, csv_data
from mongodb import get_fields_count,threat_level
from main import phishing_detector, train_phishing_model
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from werkzeug.security import generate_password_hash, check_password_hash
import joblib
import requests
from tld import get_tld
import re
import os
from urllib.parse import urlparse
import pandas as pd
import numpy as np
import pymongo
from flask import session

app = Flask(__name__)
app.secret_key = "a1f867c4439a77aa52b7cd364bbbd7ea99f4659204d0cd2d"

client = pymongo.MongoClient("mongodb://localhost:27017")
db = client['hackattack']
users_collection = db['users']

@app.route("/", methods=['GET'])
def index():
    return render_template('login.html')

@app.route("/mail")
def home():
    if 'userid' not in session:
        return redirect('/login')
    dataset_count = csv_data()
    user_count = get_fields_count()
    feedback_count = 125
    stats = {"dataset_count": dataset_count, "user_count": user_count, "feedback_count": feedback_count}
    return render_template('mail.html', result=0, stats=stats)


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        userid = request.form['userid']
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect('/signup')

        # Check if user already exists
        existing_user = users_collection.find_one({'userid': userid})
        if existing_user:
            flash('User ID already exists!', 'error')
            return redirect('/signup')

        # Save user
        hashed = generate_password_hash(password)
        users_collection.insert_one({
            'userid': userid,
            'name': name,
            'email': email,
            'password': hashed
        })
        flash('Account created successfully. Please log in.', 'success')
        return redirect('/login')
    return render_template('signup.html')


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userid = request.form['userid']
        password = request.form['password']

        user = users_collection.find_one({'userid': userid})
        if not user:
            flash('User ID not found!', 'error')
            return redirect('/login')

        if not check_password_hash(user['password'], password):
            flash('Incorrect password!', 'error')
            return redirect('/login')

        session['userid'] = userid
        return redirect('/mail')
    return render_template('login.html')

@app.route("/logout")
def logout():
    session.clear()
    return redirect('/login')


@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    features, final_url = extract_features(url)
    model = get_model()
    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0][1]
    
    result = {
        'is_phishing': bool(prediction),
        'probability': float(probability),
        'url': url,
        'final_url': final_url if url != final_url else None
    }
    
    return jsonify(result)

def get_final_url(url):
    try:
        # Follow redirects to get the final URL
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except:
        return url

# Features extraction functions
def extract_features(url):
    features = []
    
    # Get final URL if it's a shortened URL
    final_url = get_final_url(url)
    
    # URL length
    features.append(len(final_url))
    
    # Number of dots
    features.append(final_url.count('.'))
    
    # Number of hyphens
    features.append(final_url.count('-'))
    
    # Number of underscores
    features.append(final_url.count('_'))
    
    # Number of slashes
    features.append(final_url.count('/'))
    
    # Number of question marks
    features.append(final_url.count('?'))
    
    # Number of equals
    features.append(final_url.count('='))
    
    # Number of @ symbols
    features.append(final_url.count('@'))
    
    # Number of & symbols
    features.append(final_url.count('&'))
    
    # Number of digits
    features.append(sum(c.isdigit() for c in final_url))
    
    # Check if URL contains IP address
    features.append(1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', final_url) else 0)
    
    # Check if URL uses HTTPS
    features.append(1 if final_url.startswith('https://') else 0)
    
    # Get domain information
    try:
        domain = get_tld(final_url, as_object=True)
        features.append(len(domain.domain))
        features.append(len(domain.tld))
    except:
        features.append(0)
        features.append(0)
    
    return features, final_url

# Load or train model
def get_model():
    if os.path.exists('phishing_model.joblib'):
        return joblib.load('phishing_model.joblib')
    else:
        # Load dataset (you would need to provide your own dataset)
        # For now, we'll create a simple model with some example data
        X = np.array([
            extract_features('https://www.google.com')[0],
            extract_features('https://www.facebook.com')[0],
            extract_features('https://www.phishing-example.com')[0],
            extract_features('https://www.secure-bank.com')[0],
        ])
        y = np.array([0, 0, 1, 0])  # 0 for legitimate, 1 for phishing
        
        model = RandomForestClassifier(n_estimators=100)
        model.fit(X, y)
        joblib.dump(model, 'phishing_model.joblib')
        return model


@app.route("/sms")
def display_sms():
    dataset_count = csv_data()
    user_count = get_fields_count()
    feedback_count = 125

    stats = {
        "dataset_count": dataset_count,
        "user_count": user_count,
        "feedback_count": feedback_count
    }

    return render_template('sms.html', 
                           result=0,
                           stats=stats
                           )

@app.route("/sms/result", methods=['POST'])
def display_sms_result():
    dataset_count = csv_data()
    user_count = get_fields_count()
    feedback_count = 125

    stats = {
        "dataset_count": dataset_count,
        "user_count": user_count,
        "feedback_count": feedback_count
    }

    phone = request.form['senderPhone']
    sms_content = request.form['senderSMS']
    consent = request.form.getlist('consent')



    mongo_response = threat_level(phone)

    consent = 1 if consent == ['1'] else 0

    print(phone, sms_content, consent)

    spam = spam_detector(phone, sms_content, consent)
    return render_template('sms.html',
                           result=1, 
                           spam=spam,
                           phone=phone,
                           sms_content=sms_content,
                           mongo_response=mongo_response,
                           consent=consent,
                           stats=stats
                           )


@app.route("/sms/result/isspam", methods=['POST'])
def sms_isspam():
    dataset_count = csv_data()
    user_count = get_fields_count()
    feedback_count = 125

    phone = request.form['senderPhone']
   
    stats = {
        "dataset_count": dataset_count,
        "user_count": user_count,
        "feedback_count": feedback_count
    }

    response = {
        "type": 'sms',
        "id": phone,
        "isspam": 0
    }

    return render_template('feedback.html', 
                            response=response,
                            stats=stats
                           )


@app.route("/sms/result/notspam", methods=['POST'])
def sms_notspam():
    dataset_count = csv_data()
    user_count = get_fields_count()
    feedback_count = 125

    phone = request.form['senderPhone']

    stats = {
        "dataset_count": dataset_count,
        "user_count": user_count,
        "feedback_count": feedback_count
    }

    response = {
        "type": 'sms',
        "id": phone,
        "isspam": 0
    }

    return render_template('feedback.html',
                           response=response,
                           stats=stats
                           )




@app.route("/mail/result", methods=['POST'])
def display_mail_result():
    dataset_count = csv_data()
    user_count = get_fields_count()
    feedback_count = 125

    stats = {
        "dataset_count": dataset_count,
        "user_count": user_count,
        "feedback_count": feedback_count
    }

    email = request.form['senderMail']
    email_content = request.form['senderMailContent']
    consent = request.form.getlist('consent')

    mongo_response = threat_level(email)

    consent = 1 if consent == ['1'] else 0

    spam = spam_detector(email, email_content, consent)

    return render_template('mail.html', 
                            result=1, 
                            spam=spam,
                            email=email,
                            email_content=email_content,
                            consent=consent,
                            mongo_response=mongo_response,
                            stats=stats)

@app.route("/mail/result/isspam", methods=['POST'])
def mail_isspam():
    dataset_count = csv_data()
    user_count = get_fields_count()
    feedback_count = 125

    email = request.form['senderMail']

    stats = {
        "dataset_count": dataset_count,
        "user_count": user_count,
        "feedback_count": feedback_count
    }

    response = {
        "type": 'email',
        "id": email,
        "isspam": 0
    }

    return render_template('feedback.html', 
                           response=response,
                           stats=stats
                           )

@app.route("/mail/result/notspam", methods=['POST'])
def mail_notspam():
    dataset_count = csv_data()
    user_count = get_fields_count()
    feedback_count = 125

    email = request.form['senderMail']

    stats = {
        "dataset_count": dataset_count,
        "user_count": user_count,
        "feedback_count": feedback_count
    }

    response = {
        "type": 'email',
        "id": email,
        "isspam": 1
    }

    return render_template('feedback.html', 
                           response=response,
                           stats=stats
                           )

if not os.path.exists("phishing.pkl") or not os.path.exists("phishing_vectorizer.pkl"):
    train_phishing_model()

@app.route("/phishing")
def phishing_page():
    dataset_count = csv_data()
    user_count = get_fields_count()
    feedback_count = 125

    stats = {
        "dataset_count": dataset_count,
        "user_count": user_count,
        "feedback_count": feedback_count
    }

    return render_template('phishing.html',
                           result=0,
                           stats=stats
                           )

@app.route("/phishing/result", methods=['POST'])
def phishing_result():
    dataset_count = csv_data()
    user_count = get_fields_count()
    feedback_count = 125

    stats = {
        "dataset_count": dataset_count,
        "user_count": user_count,
        "feedback_count": feedback_count
    }

    content = request.form['phishingContent']
    consent = request.form.get('consent')
    consent = 1 if consent == '1' else 0

    result = phishing_detector(content)
    # If phishing_detector returns True for phishing
    is_phishing = result
    probability = 0.85  # Replace with your own logic
    final_url = content  # Or get_final_url(content)

    return render_template('phishing.html',
                       result=1,
                       content=content,
                       is_phishing=result,
                       probability=0.87,  # example
                       final_url=content,  # or resolved
                       consent=consent,
                       stats=stats)


@app.route("/phishing/result/isspam", methods=['POST'])
def phishing_isspam():
    url = request.form['url']
    response = {
        "type": 'phishing',
        "id": url,
        "isspam": 1
    }
    return render_template('feedback.html', response=response)

@app.route("/phishing/result/notspam", methods=['POST'])
def phishing_notspam():
    url = request.form['url']
    response = {
        "type": 'phishing',
        "id": url,
        "isspam": 0
    }
    return render_template('feedback.html', response=response)


if __name__ == "__main__":
    # app.run(host="0.0.0.0", port=8080)
    app.run()