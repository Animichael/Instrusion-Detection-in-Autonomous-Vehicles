from flask import request, jsonify
from datetime import datetime
import numpy as np
import pickle
import os

# Get the current directory
current_dir = os.path.dirname(os.path.abspath(__file__))

def init_model():
    try:
        # Load only the model
        model_path = os.path.join(current_dir, 'intrusion_model.pkl')
        
        print(f"Loading model from: {model_path}")  # Debug print
        
        if not os.path.exists(model_path):
            print("Model file not found!" )
            return None

        # Load model
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        
        print("Model loaded successfully!")  # Debug print
        return model
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        return None

model = init_model()

def predict_intrusion(app, db, AttackDetection):  # Add db and AttackDetection as parameters
    @app.route('/predict', methods=['POST'])
    def predict():
        if model is None:
            return jsonify({"error": "Model not loaded properly. Check if file exists."})
            
        try:
            # Get input data from request
            data = request.json
            
            # Debug print
            print(f"Received data: {data}")
            
            # Parse inputs directly without scaling
            input_data = np.array([[
                float(data.get('CAN_ID', 0)),
                float(data.get('payload_byte1', 0)),
                float(data.get('payload_byte2', 0)),
                float(data.get('payload_byte3', 0)),
                float(data.get('payload_byte4', 0)),
                float(data.get('payload_byte5', 0)),
                float(data.get('payload_byte6', 0)),
                float(data.get('payload_byte7', 0)),
                float(data.get('payload_byte8', 0)),
                float(data.get('is_zero_payload', 0))
            ]])
            
            # Debug print
            print(f"Prepared input data: {input_data}")
            
            # Make prediction directly without scaling
            prediction = model.predict(input_data)[0]
            
            # Map prediction to attack type
            attack_types = {
                0: "There is no threat",
                1: "DoS Attack",
                2: "Fuzzy Attack",
                3: "RPM Attack",
                4: "gear Attack"
            }
            result = attack_types.get(prediction, "Invalid prediction")
            
            # Save attack detection if it's not "There is no threat"
            if result != "There is no threat":
                try:
                    attack_record = AttackDetection(
                        vehicle_model=data.get('vehicle_model'),
                        device_id=data.get('device_id'),
                        can_id=str(data.get('CAN_ID')),
                        attack_type=result,
                        status="Attack",
                        detected_at=datetime.now()
                    )
                    db.session.add(attack_record)
                    db.session.commit()
                    print(f"Attack record saved: {attack_record}")
                except Exception as e:
                    print(f"Error saving attack record: {str(e)}")
                    db.session.rollback()
            
            return jsonify({"prediction": result})
        
        except Exception as e:
            print(f"Prediction error: {str(e)}")  # Debug print
            return jsonify({"error": str(e)})