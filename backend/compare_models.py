import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from feature_extractor import extract_features


# --------------------------------
# 1. Load Dataset
# --------------------------------

print("Loading dataset...")

data = pd.read_csv("../data/combined_urls.csv")

print("Total URLs:", len(data))


# --------------------------------
# 2. Extract Features
# --------------------------------

print("\nExtracting features...")

X = []
y = []

for _, row in data.iterrows():

    url = row["url"]
    label = row["label"]

    features = extract_features(url)

    X.append(features)
    y.append(label)


print("Feature extraction completed!")


# --------------------------------
# 3. Split Dataset
# --------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# --------------------------------
# 4. Create Models
# --------------------------------

models = {

    "Random Forest": RandomForestClassifier(
        n_estimators=100,
        random_state=42
    ),

    "Decision Tree": DecisionTreeClassifier(
        random_state=42
    ),

    "Logistic Regression": LogisticRegression(
        max_iter=1000,
        random_state=42
    )
}


# --------------------------------
# 5. Train & Compare
# --------------------------------

results = []

for name, model in models.items():

    print("\nTraining:", name)

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)

    results.append([
        name,
        accuracy,
        precision,
        recall,
        f1
    ])


# --------------------------------
# 6. Display Results
# --------------------------------

print("\n==========================================")
print("       MACHINE LEARNING COMPARISON")
print("==========================================")

print(
    f"{'Algorithm':<22}"
    f"{'Accuracy':<12}"
    f"{'Precision':<12}"
    f"{'Recall':<12}"
    f"{'F1-Score':<12}"
)

print("-" * 68)

for result in results:

    name, accuracy, precision, recall, f1 = result

    print(
        f"{name:<22}"
        f"{accuracy * 100:<12.2f}"
        f"{precision:<12.2f}"
        f"{recall:<12.2f}"
        f"{f1:<12.2f}"
    )


# --------------------------------
# 7. Find Best Model
# --------------------------------

best_model = max(results, key=lambda x: x[4])

print("\n==========================================")
print("BEST MODEL")
print("==========================================")

print("Algorithm:", best_model[0])
print("F1-Score:", round(best_model[4], 4))
print("Accuracy:", round(best_model[1] * 100, 2), "%")

print("\nModel comparison completed!")