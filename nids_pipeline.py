import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
import os
import joblib

def main():
    print("=== CyberGuard NIDS Pipeline ===")
    
    # 1. Load the dataset
    data_path = 'data/cyberguard_synthetic_demo (1).csv' if os.path.exists('data/cyberguard_synthetic_demo (1).csv') else 'cyberguard_synthetic_demo (1).csv'
    df = pd.read_csv(data_path)
    
    # 2. Investigate Artificial Labels / Data Leakage
    # As observed in preliminary analysis, ID perfectly correlates with attack_type 
    # because the dataset is sequentially ordered by ID per class.
    # Therefore, keeping ID would be a severe data leak.
    if 'ID' in df.columns:
        print("\nDropping 'ID' column to prevent artificial data leakage...")
        df.drop(columns=['ID'], inplace=True)
    
    # 3. Separate features and target
    target_col = 'attack_type'
    X = df.drop(columns=[target_col])
    y = df[target_col]
    
    # Encode target labels
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    # 4. Train/Test Split (Stratified to maintain class distributions)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    # 5. Preprocessing
    # Identify numerical and categorical columns
    num_cols = X_train.select_dtypes(include=['int64', 'float64']).columns.tolist()
    cat_cols = X_train.select_dtypes(include=['object', 'category', 'string']).columns.tolist()
    
    print(f"\nNumerical features: {num_cols}")
    print(f"Categorical features: {cat_cols}")
    
    # Define transformers
    numeric_transformer = StandardScaler()
    categorical_transformer = OneHotEncoder(handle_unknown='ignore')
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, num_cols),
            ('cat', categorical_transformer, cat_cols)
        ]
    )
    
    # 6. Model Setup
    # Using RandomForest to handle non-linear relationships and interactions robustly
    
    
    model = RandomForestClassifier(n_estimators=150, random_state=42, max_depth=20, class_weight='balanced') #improves accuracy
    #model = RandomForestClassifier(n_estimators=100, random_state=42,  class_weight='balanced')
    
    pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', model)
    ])
    
    # 7. Training
    print("\nTraining the Random Forest model...")
    pipeline.fit(X_train, y_train)
    
    # 8. Evaluation (Honest evaluation on test set only)
    print("\nEvaluating the model on the test set...")
    y_pred = pipeline.predict(X_test)
    
    acc = accuracy_score(y_test, y_pred)
    print(f"\nTest Accuracy: {acc:.4f}")
    print(f"Accuracy:          {accuracy_score(y_test, y_pred):.4f}")
    print(f"Balanced Accuracy: {balanced_accuracy_score(y_test, y_pred):.4f}")

    print(f"Macro Precision:   {precision_score(y_test, y_pred, average='macro', zero_division=0):.4f}")
    print(f"Macro Recall:      {recall_score(y_test, y_pred, average='macro', zero_division=0):.4f}")
    print(f"Macro F1-score:    {f1_score(y_test, y_pred, average='macro', zero_division=0):.4f}")

   
    
    print("\n=== Classification Report ===")
    target_names = le.inverse_transform(np.unique(y_encoded))
    print(classification_report(y_test, y_pred, target_names=target_names))
    
    print("\n=== Confusion Matrix ===")
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=target_names, yticklabels=target_names)
    plt.title('Confusion Matrix on Test Set')
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png')
    print("Saved confusion matrix as 'confusion_matrix.png'")
    
#     # 9. Feature Importance Analysis
#     print("\nExtracting feature importances to investigate model behavior...")
#     # Get feature names after one-hot encoding
#     cat_feature_names = pipeline.named_steps['preprocessor'].named_transformers_['cat'].get_feature_names_out(cat_cols)
#     all_feature_names = num_cols + cat_feature_names.tolist()
    
#     importances = pipeline.named_steps['classifier'].feature_importances_
    
#     feature_importance_df = pd.DataFrame({
#         'Feature': all_feature_names,
#         'Importance': importances
#     }).sort_values(by='Importance', ascending=False)
    
#     print("\nTop 10 Most Important Features:")
#     print(feature_importance_df.head(10))
    
#     # Save the pipeline for future use
#     os.makedirs('models', exist_ok=True)
#     joblib.dump(pipeline, 'models/nids_pipeline.pkl')
#     joblib.dump(le, 'models/label_encoder.pkl')
#     print("\nModel pipeline and label encoder saved successfully to models/ directory.")

if __name__ == "__main__":
    main()