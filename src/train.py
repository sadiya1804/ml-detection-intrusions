import pandas as pd
import numpy as np
import os
import joblib
import logging
import time
from typing import Dict, Any, Tuple
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import GridSearchCV
import matplotlib.pyplot as plt
import seaborn as sns

# Import local modules
from data_loader import prepare_data_for_training

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('logs', 'train.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create necessary directories
os.makedirs('logs', exist_ok=True)
os.makedirs('models', exist_ok=True)
os.makedirs(os.path.join('models', 'plots'), exist_ok=True)

def train_random_forest(X_train: pd.DataFrame, y_train: pd.Series, 
                        X_test: pd.DataFrame = None, y_test: pd.Series = None,
                        hyperparameter_tuning: bool = False) -> Tuple[RandomForestClassifier, Dict[str, Any]]:
    """
    Train a Random Forest classifier
    
    Args:
        X_train: Training features
        y_train: Training labels
        X_test: Testing features (optional)
        y_test: Testing labels (optional)
        hyperparameter_tuning: Whether to perform hyperparameter tuning
        
    Returns:
        Trained model and performance metrics
    """
    logger.info("Training Random Forest classifier...")
    start_time = time.time()
    
    if hyperparameter_tuning:
        logger.info("Performing hyperparameter tuning...")
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [None, 10, 20, 30],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        grid_search = GridSearchCV(
            RandomForestClassifier(random_state=42),
            param_grid=param_grid,
            cv=3,
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        best_params = grid_search.best_params_
        logger.info(f"Best parameters: {best_params}")
        
        model = grid_search.best_estimator_
    else:
        # Use default parameters
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=30,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_train, y_train)
    
    training_time = time.time() - start_time
    logger.info(f"Training completed in {training_time:.2f} seconds")
    
    # Evaluate model if test data is provided
    metrics = {}
    if X_test is not None and y_test is not None:
        metrics = evaluate_model(model, X_test, y_test)
    
    return model, metrics

def train_gradient_boosting(X_train: pd.DataFrame, y_train: pd.Series, 
                           X_test: pd.DataFrame = None, y_test: pd.Series = None,
                           hyperparameter_tuning: bool = False) -> Tuple[GradientBoostingClassifier, Dict[str, Any]]:
    """
    Train a Gradient Boosting classifier
    
    Args:
        X_train: Training features
        y_train: Training labels
        X_test: Testing features (optional)
        y_test: Testing labels (optional)
        hyperparameter_tuning: Whether to perform hyperparameter tuning
        
    Returns:
        Trained model and performance metrics
    """
    logger.info("Training Gradient Boosting classifier...")
    start_time = time.time()
    
    if hyperparameter_tuning:
        logger.info("Performing hyperparameter tuning...")
        param_grid = {
            'n_estimators': [100, 200],
            'learning_rate': [0.01, 0.1, 0.2],
            'max_depth': [3, 5, 7],
            'min_samples_split': [2, 5],
            'min_samples_leaf': [1, 2]
        }
        
        grid_search = GridSearchCV(
            GradientBoostingClassifier(random_state=42),
            param_grid=param_grid,
            cv=3,
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        best_params = grid_search.best_params_
        logger.info(f"Best parameters: {best_params}")
        
        model = grid_search.best_estimator_
    else:
        # Use default parameters
        model = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=3,
            min_samples_split=2,
            min_samples_leaf=1,
            random_state=42
        )
        model.fit(X_train, y_train)
    
    training_time = time.time() - start_time
    logger.info(f"Training completed in {training_time:.2f} seconds")
    
    # Evaluate model if test data is provided
    metrics = {}
    if X_test is not None and y_test is not None:
        metrics = evaluate_model(model, X_test, y_test)
    
    return model, metrics

def evaluate_model(model, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
    """
    Evaluate a trained model on test data
    
    Args:
        model: Trained model
        X_test: Test features
        y_test: Test labels
        
    Returns:
        Dictionary containing evaluation metrics
    """
    logger.info("Evaluating model on test data...")
    
    # Make predictions
    y_pred = model.predict(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    class_report = classification_report(y_test, y_pred, output_dict=True)
    conf_matrix = confusion_matrix(y_test, y_pred)
    
    # Log results
    logger.info(f"Accuracy: {accuracy:.4f}")
    logger.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")
    
    # Create confusion matrix plot
    plt.figure(figsize=(10, 8))
    sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues',
                xticklabels=sorted(y_test.unique()),
                yticklabels=sorted(y_test.unique()))
    plt.xlabel('Predicted')
    plt.ylabel('True')
    plt.title('Confusion Matrix')
    
    # Save the plot
    plot_path = os.path.join('models', 'plots', f'{type(model).__name__}_confusion_matrix.png')
    plt.savefig(plot_path)
    plt.close()
    logger.info(f"Confusion matrix saved to {plot_path}")
    
    # Return metrics as dictionary
    metrics = {
        'accuracy': accuracy,
        'classification_report': class_report,
        'confusion_matrix': conf_matrix.tolist(),
        'plot_path': plot_path
    }
    
    return metrics

def train_svm(X_train: pd.DataFrame, y_train: pd.Series, 
             X_test: pd.DataFrame = None, y_test: pd.Series = None,
             hyperparameter_tuning: bool = False) -> Tuple[SVC, Dict[str, Any]]:
    """Train an SVM classifier"""
    logger.info("Training SVM classifier...")
    start_time = time.time()
    
    if hyperparameter_tuning:
        logger.info("Performing hyperparameter tuning...")
        param_grid = {
            'C': [0.1, 1, 10, 100],
            'gamma': ['scale', 'auto', 0.1, 0.01],
            'kernel': ['rbf', 'linear']
        }
        
        grid_search = GridSearchCV(
            SVC(probability=True, random_state=42),
            param_grid=param_grid,
            cv=3,
            n_jobs=-1,
            verbose=1
        )
        
        grid_search.fit(X_train, y_train)
        best_params = grid_search.best_params_
        logger.info(f"Best parameters: {best_params}")
        
        model = grid_search.best_estimator_
    else:
        # Use default parameters
        model = SVC(probability=True, random_state=42)
        model.fit(X_train, y_train)
    
    training_time = time.time() - start_time
    logger.info(f"Training completed in {training_time:.2f} seconds")
    
    # Evaluate model if test data is provided
    metrics = {}
    if X_test is not None and y_test is not None:
        metrics = evaluate_model(model, X_test, y_test)
    
    return model, metrics

def save_model(model, model_name: str = "intrusion_detection_model"):
    """Save the trained model to disk"""
    model_path = os.path.join('models', f'{model_name}.pkl')
    joblib.dump(model, model_path)
    logger.info(f"Model saved to {model_path}")
    return model_path

if __name__ == "__main__":
    logger.info("Starting intrusion detection model training...")
    
    # Prepare data
    X_train, X_test, y_train, y_test = prepare_data_for_training()
    
    # Train models
    models = {}
    metrics = {}
    
    # Random Forest
    rf_model, rf_metrics = train_random_forest(
        X_train, y_train, X_test, y_test, 
        hyperparameter_tuning=False
    )
    models['random_forest'] = rf_model
    metrics['random_forest'] = rf_metrics
    
    # Gradient Boosting
    gb_model, gb_metrics = train_gradient_boosting(
        X_train, y_train, X_test, y_test, 
        hyperparameter_tuning=False
    )
    models['gradient_boosting'] = gb_model
    metrics['gradient_boosting'] = gb_metrics
    
    # Select the best model based on accuracy
    best_model_name = max(metrics, key=lambda k: metrics[k]['accuracy'])
    best_model = models[best_model_name]
    
    logger.info(f"Best model: {best_model_name} with accuracy {metrics[best_model_name]['accuracy']:.4f}")
    
    # Save the best model
    save_model(best_model, "intrusion_detection_model")
    
    logger.info("Training completed successfully!")
