import pandas as pd
import os

from feature_extractor import extract_features


# --------------------------------------------------
# 1. Define file paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

INPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "combined_urls.csv"
)

OUTPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "features_dataset.csv"
)


# --------------------------------------------------
# 2. Read the combined dataset
# --------------------------------------------------

print("Reading combined dataset...")

df = pd.read_csv(INPUT_FILE)

print("Total URLs found:", len(df))


# --------------------------------------------------
# 3. Extract features
# --------------------------------------------------

print("\nExtracting 12 features from URLs...")

feature_data = []

total = len(df)

for index, url in enumerate(df["url"]):

    try:
        features = extract_features(str(url))

        feature_data.append(features)

    except Exception as e:
        print("Error processing URL:", url)
        print("Error:", e)

        # Add 12 zero values if a URL causes an error
        feature_data.append([0] * 12)

    # Show progress every 5000 URLs
    if (index + 1) % 5000 == 0:
        print(
            f"Processed {index + 1} / {total} URLs"
        )


# --------------------------------------------------
# 4. Create feature column names
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


# --------------------------------------------------
# 5. Create feature DataFrame
# --------------------------------------------------

features_df = pd.DataFrame(
    feature_data,
    columns=feature_columns
)


# --------------------------------------------------
# 6. Add original URL and label
# --------------------------------------------------

features_df.insert(
    0,
    "url",
    df["url"].values
)

features_df["label"] = df["label"].values


# --------------------------------------------------
# 7. Save the feature dataset
# --------------------------------------------------

features_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# --------------------------------------------------
# 8. Display results
# --------------------------------------------------

print("\nFeature extraction completed!")

print(
    "Final dataset shape:",
    features_df.shape
)

print("\nFeature columns:")
print(features_df.columns.tolist())

print("\nClass distribution:")
print(features_df["label"].value_counts())

print("\nSaved file:")
print(os.path.abspath(OUTPUT_FILE))