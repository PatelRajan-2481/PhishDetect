import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# Load and clean dataset
df = pd.read_csv("Phishing_Email.csv")
df = df.dropna(subset=["Email Text", "Email Type"])  # remove rows with nulls
df = df[df["Email Text"].str.strip().astype(bool)]   # remove empty/blank text

# Add extra safe emails to reduce false positives
extra_safe = [
    ("Thank you for your purchase! Your order #12345 has shipped.", "Safe Email"),
    ("Your payment has been successfully received.", "Safe Email"),
    ("We appreciate your feedback on our service.", "Safe Email"),
    ("Track your Amazon delivery using the link below", "Safe Email"),
    ("Here is your invoice for this month’s subscription", "Safe Email"),
]
df_extra = pd.DataFrame(extra_safe, columns=["Email Text", "Email Type"])
df = pd.concat([df, df_extra], ignore_index=True)

# Map labels to 'safe'/'malicious'
df["label"] = df["Email Type"].apply(lambda x: "malicious" if "Phishing" in x else "safe")
X = df["Email Text"]
y = df["label"]

# Vectorize
vectorizer = TfidfVectorizer(max_features=3000, stop_words='english')
X_vect = vectorizer.fit_transform(X)

# Train/test split and model
X_train, X_test, y_train, y_test = train_test_split(X_vect, y, test_size=0.2, random_state=42)
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Save model
os.makedirs("ml_model", exist_ok=True)
joblib.dump(clf, "ml_model/email_model.joblib")
joblib.dump(vectorizer, "ml_model/vectorizer.joblib")

print("✅ Trained Random Forest email classifier using Kaggle dataset.")


from sklearn.metrics import classification_report, confusion_matrix

# Predict on test set
y_pred = clf.predict(X_test)

# Print full classification report
print("\n📊 MODEL PERFORMANCE REPORT:")
print(classification_report(y_test, y_pred))

# Print confusion matrix
print("\n🔁 CONFUSION MATRIX:")
print(confusion_matrix(y_test, y_pred))


