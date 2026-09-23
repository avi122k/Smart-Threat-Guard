import pandas as pd
import pickle
import os

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# --------------------------------------------------
# 1. Define file paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DATA_FILE = os.path.join(
    BASE_DIR,
    "data",
    "features_dataset.csv"
)

MODEL_FILE = os.path.join(
    BASE_DIR,
    "backend",
    "model.pkl"
)


# --------------------------------------------------
# 2. Load Feature Dataset
# --------------------------------------------------

print("Loading feature dataset...")

data = pd.read_csv(DATA_FILE)

print("Dataset loaded successfully!")
print("Total records:", len(data))


# --------------------------------------------------
# 3. Select Features and Labels
# --------------------------------------------------

feature_columns = [
    "url_length",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "at_count",
    "digit_count",
    "special_count",
    "subdomain_count",
    "path_length",
    "query_length",
    "ip_usage",
    "suspicious_count"
]

X = data[feature_columns]

y = data["label"]


print("\nNumber of features:", len(feature_columns))

print("Features:")
print(feature_columns)


# --------------------------------------------------
# 4. Display Class Distribution
# --------------------------------------------------

print("\nClass distribution:")

print(
    y.value_counts()
)


# --------------------------------------------------
# 5. Split Dataset
# --------------------------------------------------

print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))


# --------------------------------------------------
# 6. Create Random Forest Model
# --------------------------------------------------

print("\nCreating Random Forest model...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced"
)


# --------------------------------------------------
# 7. Train Model
# --------------------------------------------------

print("\nTraining Random Forest model...")

model.fit(
    X_train,
    y_train
)

print("Model training completed!")


# --------------------------------------------------
# 8. Make Predictions
# --------------------------------------------------

print("\nTesting model...")

predictions = model.predict(X_test)


# --------------------------------------------------
# 9. Calculate Accuracy
# --------------------------------------------------

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\n==============================")
print("MODEL PERFORMANCE")
print("==============================")

print(
    "\nAccuracy:",
    round(accuracy * 100, 2),
    "%"
)


# --------------------------------------------------
# 10. Classification Report
# --------------------------------------------------

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Legitimate",
            "Phishing"
        ],
        zero_division=0
    )
)


# --------------------------------------------------
# 11. Confusion Matrix
# --------------------------------------------------

matrix = confusion_matrix(
    y_test,
    predictions
)

print("\nConfusion Matrix:")

print(matrix)

print("\nMatrix meaning:")
print("True Negative :", matrix[0][0])
print("False Positive:", matrix[0][1])
print("False Negative:", matrix[1][0])
print("True Positive :", matrix[1][1])


# --------------------------------------------------
# 12. Save the trained model
# --------------------------------------------------

print("\nSaving trained model...")

with open(
    MODEL_FILE,
    "wb"
) as file:

    pickle.dump(
        model,
        file
    )


print("Model saved successfully!")

print(
    "Model location:",
    MODEL_FILE
)


# --------------------------------------------------
# 13. Final message
# --------------------------------------------------

print("\n================================")
print("40% ML TRAINING COMPLETED!")
print("================================")