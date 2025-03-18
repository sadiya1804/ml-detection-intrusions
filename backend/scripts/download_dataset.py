# download_dataset.py
import os
import urllib.request
import gzip
import shutil

# Create data directory if it doesn't exist
os.makedirs('../data', exist_ok=True)

# Download the 10 percent subset of KDD Cup 99 dataset
url = 'http://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz'
gz_file_path = '../data/kddcup.data_10_percent.gz'
output_file_path = '../data/kddcup.data_10_percent'

print(f"Downloading dataset from {url}...")
urllib.request.urlretrieve(url, gz_file_path)
print("Download complete.")

# Extract the gzipped file
print("Extracting dataset...")
with gzip.open(gz_file_path, 'rb') as f_in:
    with open(output_file_path, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
print(f"Dataset extracted to {output_file_path}")

# Remove the gzipped file
os.remove(gz_file_path)
print("Cleanup complete.")
