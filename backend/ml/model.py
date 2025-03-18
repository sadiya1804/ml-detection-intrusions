import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import sys
sys.path.append('..')
from data.preprocess import load_and_preprocess_data

class IntrusionDetector:
    def __init__(self):
        self.preprocessor = None
        self.model = None
        
    def train(self, data_path, test_size=0.3, random_state=42):
        # Load and preprocess data
        self.preprocessor, X, y = load_and_preprocess_data(data_path)
        
        # Transform features
        X_transformed = self.preprocessor.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_transformed, y, test_size=test_size, random_state=random_state
        )
        
        # Train model
        self.model = RandomForestClassifier(n_estimators=100, random_state=random_state)
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        print(classification_report(y_test, y_pred))
        
        return {
            'accuracy': self.model.score(X_test, y_test),
            'report': classification_report(y_test, y_pred, output_dict=True)
        }
    
    def predict(self, connection_data):
        """
        Predict if a connection is an intrusion
        
        Args:
            connection_data: DataFrame with connection features
            
        Returns:
            Dictionary with prediction results
        """
        if self.preprocessor is None or self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        
        # Transform input data
        X_transformed = self.preprocessor.transform(connection_data)
        
        # Make prediction
        prediction = self.model.predict(X_transformed)
        probabilities = self.model.predict_proba(X_transformed)
        
        # Get prediction confidence
        max_probs = np.max(probabilities, axis=1)
        
        # Log detailed prediction information
        print(f"Debug - Prediction: {prediction}")
        print(f"Debug - Probabilities shape: {probabilities.shape}")
        print(f"Debug - Top class probabilities: {max_probs}")
        
        # Get the top 3 classes with their probabilities
        top_classes = []
        for i, probs in enumerate(probabilities):
            class_probs = [(self.model.classes_[j], prob) for j, prob in enumerate(probs)]
            sorted_probs = sorted(class_probs, key=lambda x: x[1], reverse=True)[:3]
            top_classes.append(sorted_probs)
        
        print(f"Debug - Top 3 classes: {top_classes}")
        
        return {
            'prediction': prediction.tolist(),
            'probabilities': probabilities.tolist(),
            'anomaly_score': max_probs.tolist(),
            'top_classes': [[cls, float(prob)] for cls_list in top_classes for cls, prob in cls_list]
        }

    
    def save_model(self, model_path, preprocessor_path):
        """Save the trained model and preprocessor"""
        if self.model is None or self.preprocessor is None:
            raise ValueError("Model not trained. Call train() first.")
            
        joblib.dump(self.model, model_path)
        joblib.dump(self.preprocessor, preprocessor_path)
        
    def load_model(self, model_path, preprocessor_path):
        """Load a trained model and preprocessor"""
        self.model = joblib.load(model_path)
        self.preprocessor = joblib.load(preprocessor_path)

if __name__ == "__main__":
    detector = IntrusionDetector()
    results = detector.train('../data/kddcup.data_10_percent')
    print(f"Model accuracy: {results['accuracy']:.4f}")
    
    # Save model
    detector.save_model('../models/intrusion_model.pkl', 
                       '../models/intrusion_preprocessor.pkl')
