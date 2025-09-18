import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
import mongodb
import pickle
from csv import writer

def append_to_csv(csvpath, data):
    with open(csvpath, 'a') as appendObj:
        append = writer(appendObj)
        append.writerow(data)

def spam_detector(id, content, consent):
    data = pd.read_csv('static/dataset/spam.csv',encoding="latin-1")
    data.drop(['Unnamed: 2', 'Unnamed: 3', 'Unnamed: 4'], axis=1, inplace=True)
    data['v1']=data['v1'].map({'ham':0, 'spam':1})
    cv=CountVectorizer()
    x=data['v2'] #message is v2
    y=data['v1'] #spam or ham flag is v1
    x=cv.fit_transform(x)

    #CONVERTING DATA INTO TRAIN TAKS FORMAT
    x_train , x_test , y_train ,y_test = train_test_split(x,y,test_size=0.2)

    model=MultinomialNB()
    model.fit(x_train,y_train)
    
    result=model.score(x_test,y_test)
    result*100

    pickle.dump(model,open("spam.pkl","wb"))
    pickle.dump(cv,open("vectorizer.pkl","wb"))

    clf=pickle.load(open("spam.pkl","rb"))

    #-----------------------------------------------------



    test_msg=content
    data=[test_msg]
    vect=cv.transform(data).toarray()
    result=model.predict(vect)
    print(result)


    if consent==1 and result==1:
        print('consent = 1, result = 1')
        # writing in mongodb
        mongodb.is_spam(id)

        # writing the data to the csv file
        ans = 'spam' if result == [1] else 'ham'
        append_to_csv('./static/dataset/spam.csv', [ans, content,'','',''])
        
        return 1
    elif consent==1 and result==0:
        print('consent = 1, result = 0')
        # writing the data to the csv file
        ans = 'spam' if result == [1] else 'ham'
        append_to_csv('./static/dataset/spam.csv', [ans, content,'','',''])
        
        return 0
    elif consent==0 and result==1:
        print('consent = 0, result = 1')
        return 1
    else:
        print('consent = 0, result = 0')
        return 0

def csv_data():
    data = pd.read_csv('static/dataset/spam.csv',encoding="latin-1")
    return data.shape[0]

def train_phishing_model():
    print("Training phishing model...")

    # Load phishing dataset with correct columns
    data = pd.read_csv('static/dataset/phishing_dataset.csv')

    # Check if expected columns exist
    if 'text_combined' not in data.columns or 'label' not in data.columns:
        print("ERROR: Dataset must contain 'text_combined' and 'label' columns.")
        return

    x = data['text_combined']
    y = data['label']

    cv = CountVectorizer()
    x_vectorized = cv.fit_transform(x)

    x_train, x_test, y_train, y_test = train_test_split(x_vectorized, y, test_size=0.2, random_state=42)

    model = MultinomialNB()
    model.fit(x_train, y_train)

    # Save phishing model and vectorizer
    pickle.dump(model, open("phishing.pkl", "wb"))
    pickle.dump(cv, open("phishing_vectorizer.pkl", "wb"))

    score = model.score(x_test, y_test)
    print(f"✅ Phishing model trained with accuracy: {score * 100:.2f}%")

def phishing_detector(content):
    model = pickle.load(open("phishing.pkl", "rb"))
    vectorizer = pickle.load(open("phishing_vectorizer.pkl", "rb"))
    vect = vectorizer.transform([content])
    result = model.predict(vect)
    return int(result[0])  # 1 = phishing, 0 = not phishing




if __name__ == '__main__':
    train_phishing_model()  # This will generate phishing.pkl and phishing_vectorizer.pkl
    
    # Then call your detectors
    print(spam_detector('newuser@gmail.com', 'you have won a lottery worth 10,000 rupees', 1))
    print("Phishing result:", phishing_detector('Update your bank credentials immediately.'))
