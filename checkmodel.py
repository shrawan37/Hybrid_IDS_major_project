import joblib
import numpy as np

# Path to your model file
MODEL_PATH = "isolation_forest.pkl"

def main():
    try:
        # Load the model
        model = joblib.load(MODEL_PATH)
        print("✅ Model loaded successfully:", model)

        # Check if model has been fitted
        if hasattr(model, "estimators_"):
            print("✅ Model appears to be trained (estimators_ found).")
        else:
            print("❌ Model is not trained (no estimators_).")

        # Test with a sample feature vector
        sample = np.array([[120, 6, 443, 80, 2, 5]])  # Example features
        try:
            score = model.decision_function(sample)
            print("✅ Model produced a score:", score)
        except Exception as e:
            print("❌ Error when scoring sample:", e)

    except Exception as e:
        print("❌ Could not load model:", e)

if __name__ == "__main__":
    main()