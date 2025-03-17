import pandas as pd
import numpy as np
import os
import tensorflow as tf
import tensorflow_datasets as tfds
import logging
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib
from typing import Tuple, Dict, Any, List, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('logs', 'data_loader.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)
os.makedirs('models', exist_ok=True)
os.makedirs('data', exist_ok=True)

# Define column names for KDD Cup 99 dataset
COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
]

# Define categorical and numerical columns
CATEGORICAL_COLUMNS = ['protocol_type', 'service', 'flag']
NUMERICAL_COLUMNS = [col for col in COLUMN_NAMES if col not in CATEGORICAL_COLUMNS + ['label']]

# Define attack types mapping
ATTACK_TYPES = {
    'normal': 'normal',
    # DoS attacks
    'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos', 
    'smurf': 'dos', 'teardrop': 'dos', 'apache2': 'dos', 'udpstorm': 'dos', 
    'processtable': 'dos', 'worm': 'dos',
    # Probe attacks
    'satan': 'probe', 'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 
    'mscan': 'probe', 'saint': 'probe',
    # R2L attacks
    'guess_passwd': 'r2l', 'ftp_write': 'r2l', 'imap': 'r2l', 'phf': 'r2l', 
    'multihop': 'r2l', 'warezmaster': 'r2l', 'warezclient': 'r2l', 'spy': 'r2l',
    'xlock': 'r2l', 'xsnoop': 'r2l', 'snmpguess': 'r2l', 'snmpgetattack': 'r2l',
    'httptunnel': 'r2l', 'sendmail': 'r2l', 'named': 'r2l',
    # U2R attacks
    'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'rootkit': 'u2r', 'perl': 'u2r',
    'sqlattack': 'u2r', 'xterm': 'u2r', 'ps': 'u2r'
}

# Preprocessing pipeline
def create_preprocessing_pipeline() -> ColumnTransformer:
    """Create a preprocessing pipeline for the KDD Cup 99 dataset"""
    categorical_transformer = OneHotEncoder(handle_unknown='ignore')
    numerical_transformer = StandardScaler()
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numerical_transformer, NUMERICAL_COLUMNS),
            ('cat', categorical_transformer, CATEGORICAL_COLUMNS)
        ],
        remainder='drop'  # Drop columns not specified in transformers
    )
    
    return preprocessor

def load_kdd_cup_from_tensorflow() -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load KDD Cup 99 dataset using TensorFlow Datasets"""
    try:
        logger.info("Loading KDD Cup 99 dataset from TensorFlow Datasets...")
        
        # Load the dataset
        ds_train, ds_test = tfds.load(
            'kddcup99', 
            split=['train', 'test'],
            as_supervised=False,
            with_info=False
        )
        
        # Convert to pandas DataFrame
        train_df = tfds.as_dataframe(ds_train)
        test_df = tfds.as_dataframe(ds_test)
        
        # Rename columns to match our expected format
        train_df.columns = COLUMN_NAMES
        test_df.columns = COLUMN_NAMES
        
        # Convert label column from bytes to string
        train_df['label'] = train_df['label'].apply(lambda x: x.decode('utf-8'))
        test_df['label'] = test_df['label'].apply(lambda x: x.decode('utf-8'))
        
        # Map detailed attack types to broader categories
        train_df['attack_category'] = train_df['label'].map(
            lambda x: ATTACK_TYPES.get(x.lower(), 'unknown')
        )
        test_df['attack_category'] = test_df['label'].map(
            lambda x: ATTACK_TYPES.get(x.lower(), 'unknown')
        )
        
        logger.info(f"Loaded {len(train_df)} training samples and {len(test_df)} test samples")
        
        # Save to CSV for later use
        train_df.to_csv(os.path.join('data', 'kddcup99_train.csv'), index=False)
        test_df.to_csv(os.path.join('data', 'kddcup99_test.csv'), index=False)
        
        return train_df, test_df
    
    except Exception as e:
        logger.error(f"Error loading KDD Cup 99 dataset from TensorFlow: {str(e)}")
        raise

def load_kdd_cup_from_file(file_path: str = None) -> pd.DataFrame:
    """Load KDD Cup 99 dataset from a local file"""
    try:
        # If no file path is provided, use the default paths
        if file_path is None:
            train_path = os.path.join('data', 'kddcup99_train.csv')
            test_path = os.path.join('data', 'kddcup99_test.csv')
            
            # Check if files exist
            if os.path.exists(train_path) and os.path.exists(test_path):
                logger.info("Loading KDD Cup 99 dataset from local CSV files...")
                train_df = pd.read_csv(train_path)
                test_df = pd.read_csv(test_path)
                return train_df, test_df
            else:
                logger.info("Local CSV files not found. Loading from TensorFlow...")
                return load_kdd_cup_from_tensorflow()
        else:
            # Load from the specified file path
            logger.info(f"Loading KDD Cup 99 dataset from {file_path}...")
            df = pd.read_csv(file_path, names=COLUMN_NAMES)
            
            # Convert label column from bytes to string if needed
            if df['label'].dtype == object:
                try:
                    df['label'] = df['label'].apply(lambda x: x.decode('utf-8') if isinstance(x, bytes) else x)
                except:
                    pass
            
            # Map detailed attack types to broader categories
            df['attack_category'] = df['label'].map(
                lambda x: ATTACK_TYPES.get(str(x).lower(), 'unknown')
            )
            
            logger.info(f"Loaded {len(df)} samples from {file_path}")
            return df
    
    except Exception as e:
        logger.error(f"Error loading KDD Cup 99 dataset from file: {str(e)}")
        raise

def preprocess_data(df: pd.DataFrame, fit_pipeline: bool = False) -> pd.DataFrame:
    """
    Preprocess the data for model training or prediction
    
    Args:
        df: DataFrame containing the data to preprocess
        fit_pipeline: Whether to fit the preprocessing pipeline or use a saved one
        
    Returns:
        Preprocessed DataFrame
    """
    try:
        pipeline_path = os.path.join('models', 'preprocessing_pipeline.pkl')
        
        if fit_pipeline:
            logger.info("Fitting preprocessing pipeline...")
            preprocessor = create_preprocessing_pipeline()
            preprocessor.fit(df)
            
            # Save the preprocessing pipeline
            joblib.dump(preprocessor, pipeline_path)
            logger.info(f"Preprocessing pipeline saved to {pipeline_path}")
        else:
            # Load the preprocessing pipeline if it exists
            if os.path.exists(pipeline_path):
                logger.info(f"Loading preprocessing pipeline from {pipeline_path}")
                preprocessor = joblib.load(pipeline_path)
            else:
                logger.warning("Preprocessing pipeline not found. Creating and fitting a new one...")
                preprocessor = create_preprocessing_pipeline()
                preprocessor.fit(df)
                joblib.dump(preprocessor, pipeline_path)
        
        # Transform the data
        X_transformed = preprocessor.transform(df)
        
        # Convert to DataFrame with appropriate feature names
        feature_names = []
        
        # Get feature names for numerical columns (they stay the same)
        feature_names.extend(NUMERICAL_COLUMNS)
        
        # Get feature names for categorical columns (they are one-hot encoded)
        cat_encoder = preprocessor.named_transformers_['cat']
        cat_features = []
        for i, col in enumerate(CATEGORICAL_COLUMNS):
            cat_values = cat_encoder.categories_[i]
            cat_features.extend([f"{col}_{val}" for val in cat_values])
        
        feature_names.extend(cat_features)
        
        # Create DataFrame with transformed data
        X_df = pd.DataFrame(X_transformed, columns=feature_names)
        
        return X_df
    
    except Exception as e:
        logger.error(f"Error preprocessing data: {str(e)}")
        raise

def prepare_data_for_training() -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Prepare data for model training
    
    Returns:
        X_train: Training features
        X_test: Testing features
        y_train: Training labels
        y_test: Testing labels
    """
    try:
        # Load data
        train_df, test_df = load_kdd_cup_from_file()
        
        # Extract features and labels
        X_train = train_df.drop(['label', 'attack_category'], axis=1)
        y_train = train_df['attack_category']
        
        X_test = test_df.drop(['label', 'attack_category'], axis=1)
        y_test = test_df['attack_category']
        
        # Preprocess data
        X_train_processed = preprocess_data(X_train, fit_pipeline=True)
        X_test_processed = preprocess_data(X_test, fit_pipeline=False)
        
        logger.info(f"Prepared {len(X_train_processed)} training samples and {len(X_test_processed)} test samples")
        
        return X_train_processed, X_test_processed, y_train, y_test
    
    except Exception as e:
        logger.error(f"Error preparing data for training: {str(e)}")
        raise

def generate_sample_data(n_samples: int = 100) -> pd.DataFrame:
    """
    Generate sample data for testing
    
    Args:
        n_samples: Number of samples to generate
        
    Returns:
        DataFrame with sample data
    """
    try:
        logger.info(f"Generating {n_samples} sample data points...")
        
        # Load a small subset of real data to get the distribution
        try:
            train_df, _ = load_kdd_cup_from_file()
            sample_df = train_df.sample(n=min(n_samples * 10, len(train_df)))
            
            # If we successfully loaded real data, return a sample
            return sample_df.head(n_samples)
            
        except:
            # If loading fails, create synthetic data
            logger.warning("Could not load real data. Creating synthetic data...")
            
            # Create synthetic data with reasonable distributions
            data = {
                'duration': np.random.exponential(scale=100, size=n_samples),
                'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], size=n_samples),
                'service': np.random.choice(['http', 'ftp', 'smtp', 'ssh', 'dns'], size=n_samples),
                'flag': np.random.choice(['SF', 'REJ', 'S0', 'RSTO'], size=n_samples),
                'src_bytes': np.random.exponential(scale=1000, size=n_samples),
                'dst_bytes': np.random.exponential(scale=2000, size=n_samples),
                'land': np.random.choice([0, 1], size=n_samples, p=[0.99, 0.01]),
                'wrong_fragment': np.random.choice([0, 1], size=n_samples, p=[0.95, 0.05]),
                'urgent': np.random.choice([0, 1], size=n_samples, p=[0.98, 0.02]),
                'hot': np.random.poisson(lam=0.1, size=n_samples),
                'num_failed_logins': np.random.poisson(lam=0.05, size=n_samples),
                'logged_in': np.random.choice([0, 1], size=n_samples),
                'num_compromised': np.random.poisson(lam=0.01, size=n_samples),
                'root_shell': np.random.choice([0, 1], size=n_samples, p=[0.99, 0.01]),
                'su_attempted': np.random.choice([0, 1], size=n_samples, p=[0.99, 0.01]),
                'num_root': np.random.poisson(lam=0.01, size=n_samples),
                'num_file_creations': np.random.poisson(lam=0.1, size=n_samples),
                'num_shells': np.random.poisson(lam=0.01, size=n_samples),
                'num_access_files': np.random.poisson(lam=0.01, size=n_samples),
                'num_outbound_cmds': np.zeros(n_samples),
                'is_host_login': np.random.choice([0, 1], size=n_samples, p=[0.99, 0.01]),
                'is_guest_login': np.random.choice([0, 1], size=n_samples, p=[0.95, 0.05]),
                'count': np.random.poisson(lam=3, size=n_samples),
                'srv_count': np.random.poisson(lam=3, size=n_samples),
                'serror_rate': np.random.beta(0.5, 10, size=n_samples),
                'srv_serror_rate': np.random.beta(0.5, 10, size=n_samples),
                'rerror_rate': np.random.beta(0.5, 10, size=n_samples),
                'srv_rerror_rate': np.random.beta(0.5, 10, size=n_samples),
                'same_srv_rate': np.random.beta(5, 1, size=n_samples),
                'diff_srv_rate': np.random.beta(1, 5, size=n_samples),
                'srv_diff_host_rate': np.random.beta(1, 5, size=n_samples),
                'dst_host_count': np.random.poisson(lam=10, size=n_samples),
                'dst_host_srv_count': np.random.poisson(lam=8, size=n_samples),
                'dst_host_same_srv_rate': np.random.beta(5, 1, size=n_samples),
                'dst_host_diff_srv_rate': np.random.beta(1, 5, size=n_samples),
                'dst_host_same_src_port_rate': np.random.beta(1, 5, size=n_samples),
                'dst_host_srv_diff_host_rate': np.random.beta(1, 5, size=n_samples),
                'dst_host_serror_rate': np.random.beta(0.5, 10, size=n_samples),
                'dst_host_srv_serror_rate': np.random.beta(0.5, 10, size=n_samples),
                'dst_host_rerror_rate': np.random.beta(0.5, 10, size=n_samples),
                'dst_host_srv_rerror_rate': np.random.beta(0.5, 10, size=n_samples)
            }
            
            # Create DataFrame from synthetic data
            synthetic_df = pd.DataFrame(data)
            
            # Add a label column (mostly normal with some attacks)
            attack_types = ['normal', 'dos', 'probe', 'r2l', 'u2r']
            probabilities = [0.8, 0.1, 0.05, 0.03, 0.02]  # 80% normal, 20% attacks
            synthetic_df['label'] = np.random.choice(attack_types, size=n_samples, p=probabilities)
            
            logger.info(f"Generated {n_samples} synthetic data points")
            return synthetic_df
            
    except Exception as e:
        logger.error(f"Error generating sample data: {str(e)}")
        # Return a minimal valid DataFrame in case of error
        return pd.DataFrame({col: [0] * 10 for col in COLUMN_NAMES})
