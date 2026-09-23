from feature_extractor import extract_features


url = "http://secure-login-example.com/verify"


features = extract_features(url)


print("URL:")
print(url)

print("\nExtracted Features:")
print(features)

print("\nNumber of Features:")
print(len(features))