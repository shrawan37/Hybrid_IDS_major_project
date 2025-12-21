from sklearn.model_selection import learning_curve
import matplotlib.pyplot as plt

# Set up the Isolation Forest model
iso_forest = IsolationForest(
    n_estimators=500,
    contamination=0.46,
    max_samples=0.8,
    random_state=42
)

# Use learning_curve to calculate performance on different training sizes
train_sizes, train_scores, valid_scores = learning_curve(
    iso_forest, 
    X_train_normal, y_train_full, 
    train_sizes=np.linspace(0.1, 1.0, 10), 
    cv=5,  # 5-fold cross-validation
    scoring='accuracy',  # Use accuracy as the evaluation metric
    n_jobs=-1
)

# Calculate mean and standard deviation of the train and validation scores
train_mean = train_scores.mean(axis=1)
train_std = train_scores.std(axis=1)
valid_mean = valid_scores.mean(axis=1)
valid_std = valid_scores.std(axis=1)

# Plotting the learning curve
plt.figure(figsize=(10, 6))
plt.plot(train_sizes, train_mean, color='blue', marker='o', label='Train Accuracy')
plt.plot(train_sizes, valid_mean, color='green', marker='o', label='Validation Accuracy')

# Fill between the curves with standard deviation
plt.fill_between(train_sizes, train_mean - train_std, train_mean + train_std, alpha=0.2, color='blue')
plt.fill_between(train_sizes, valid_mean - valid_std, valid_mean + valid_std, alpha=0.2, color='green')

# Labels and Title
plt.title('Learning Curve for Isolation Forest')
plt.xlabel('Training Set Size')
plt.ylabel('Accuracy')
plt.legend(loc='best')
plt.grid(True)
plt.show()
