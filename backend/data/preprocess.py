import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

def load_and_preprocess_data(filepath):
    # Column names for KDD Cup 99 dataset
    columns = ['duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
               'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 
               'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 
               'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 
               'num_access_files', 'num_outbound_cmds', 'is_host_login', 
               'is_guest_login', 'count', 'srv_count', 'serror_rate', 
               'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 
               'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 
               'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 
               'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
               'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 
               'dst_host_srv_rerror_rate', 'label']
    
    # Load data
    df = pd.read_csv(filepath, names=columns)
    
    # Separate features and target
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Identify categorical and numerical columns
    categorical_cols = X.select_dtypes(include=['object']).columns
    numerical_cols = X.select_dtypes(exclude=['object']).columns
    
    # Create preprocessing pipelines
    numerical_transformer = Pipeline(steps=[
        ('scaler', StandardScaler())
    ])
    
    categorical_transformer = Pipeline(steps=[
        ('onehot', OneHotEncoder(handle_unknown='ignore'))
    ])
    
    # Combine preprocessing steps
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numerical_transformer, numerical_cols),
            ('cat', categorical_transformer, categorical_cols)
        ])
    
    # Return preprocessor, features, and target
    return preprocessor, X, y

if __name__ == "__main__":
    preprocessor, X, y = load_and_preprocess_data('../data/kddcup.data_10_percent')
    print(f"Data loaded: {X.shape} features, {len(np.unique(y))} classes")
