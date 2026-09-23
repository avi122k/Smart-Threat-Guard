import pandas as pd
import os

# --------------------------------------------------
# 1. Define dataset paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GOOD_FILE = os.path.join(BASE_DIR, "data", "urlsgood.csv")
PHISHING_FILE = os.path.join(BASE_DIR, "data", "urlsfish.csv")
OUTPUT_FILE = os.path.join(BASE_DIR, "data", "combined_urls.csv")

# --------------------------------------------------
# 2. Read the two CSV files
# --------------------------------------------------

print("Reading legitimate URL dataset...")
good_df = pd.read_csv(GOOD_FILE)

print("Reading phishing URL dataset...")
phishing_df = pd.read_csv(PHISHING_FILE)


# --------------------------------------------------
# 3. Display information about the datasets
# --------------------------------------------------

print("\nLegitimate dataset columns:")
print(good_df.columns.tolist())

print("\nPhishing dataset columns:")
print(phishing_df.columns.tolist())

print("\nLegitimate dataset size:", good_df.shape)
print("Phishing dataset size:", phishing_df.shape)


# --------------------------------------------------
# 4. Take the first column as the URL column
# --------------------------------------------------

good_url_column = good_df.columns[0]
phishing_url_column = phishing_df.columns[0]

good_df = good_df[[good_url_column]].copy()
phishing_df = phishing_df[[phishing_url_column]].copy()

good_df.columns = ["url"]
phishing_df.columns = ["url"]


# --------------------------------------------------
# 5. Add labels
# --------------------------------------------------

# 0 = Legitimate
# 1 = Phishing

good_df["label"] = 0
phishing_df["label"] = 1


# --------------------------------------------------
# 6. Combine both datasets
# --------------------------------------------------

combined_df = pd.concat(
    [good_df, phishing_df],
    ignore_index=True
)


# --------------------------------------------------
# 7. Remove missing URLs
# --------------------------------------------------

combined_df.dropna(subset=["url"], inplace=True)


# --------------------------------------------------
# 8. Convert URLs to string
# --------------------------------------------------

combined_df["url"] = combined_df["url"].astype(str)


# --------------------------------------------------
# 9. Remove empty URLs
# --------------------------------------------------

combined_df = combined_df[
    combined_df["url"].str.strip() != ""
]


# --------------------------------------------------
# 10. Remove duplicate URLs
# --------------------------------------------------

before_duplicates = len(combined_df)

combined_df.drop_duplicates(
    subset=["url"],
    inplace=True
)

after_duplicates = len(combined_df)

print(
    "\nDuplicate URLs removed:",
    before_duplicates - after_duplicates
)


# --------------------------------------------------
# 11. Shuffle the dataset
# --------------------------------------------------

combined_df = combined_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


# --------------------------------------------------
# 12. Save the cleaned dataset
# --------------------------------------------------

combined_df.to_csv(
    OUTPUT_FILE,
    index=False
)


# --------------------------------------------------
# 13. Display final results
# --------------------------------------------------

print("\nDataset preparation completed!")

print(
    "Final dataset size:",
    combined_df.shape
)

print("\nClass distribution:")
print(combined_df["label"].value_counts())

print("\nSaved file:")
print(os.path.abspath(OUTPUT_FILE))