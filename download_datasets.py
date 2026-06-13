import urllib.request
import os

os.makedirs('datasets', exist_ok=True)

print("Downloading NSL-KDD Train dataset...")
urllib.request.urlretrieve(
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt",
    "datasets/KDDTrain+.txt"
)
print("✅ KDDTrain+ downloaded")

urllib.request.urlretrieve(
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt",
    "datasets/KDDTest+.txt"
)
print("✅ KDDTest+ downloaded")

print("\n✅ All datasets downloaded successfully!")