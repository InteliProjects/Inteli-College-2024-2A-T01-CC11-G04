from keras.models import load_model
import joblib
import os
import numpy as np
from api.models.base.base_intent_classifier import BaseIntentClassifier

class IntentClassifier(BaseIntentClassifier):
    def __init__(self):
        self.model = self.load_model()
        self.label_encoder = self.load_label_encoder()

    def load_model(self):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')) 
        model_path = os.path.join(base_dir, 'resources', 'models', 'intent_classifier_05_09.keras')
        return load_model(model_path)
    
    def load_label_encoder(self):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
        encoder_path = os.path.join(base_dir, 'resources', 'models', 'label_encoder_05_09.pkl')
        return joblib.load(encoder_path)

    def predict(self, embeddings):
        embeddings = np.array(embeddings).reshape(1, -1)  
        prediction = self.model.predict(embeddings)
        predicted_class = np.argmax(prediction, axis=1)
        intent_name = self.label_encoder.inverse_transform([predicted_class])[0]
        return intent_name
    
if __name__ == "__main__":
    intent_classifier = IntentClassifier()
    embeddings = np.random.rand(300)
    print(intent_classifier.predict(embeddings))
