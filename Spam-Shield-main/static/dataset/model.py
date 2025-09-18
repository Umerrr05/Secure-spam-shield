import pickle

# Load the model
with open("phishing_url_detector.pkl", "rb") as f:
    model = pickle.load(f)

# Predict a new sample
test_text = ["verify your account at http://secure-login-check.com"]
prediction = model.predict(test_text)

print("Prediction:", "Phishing" if prediction[0] == 1 else "Legitimate")
