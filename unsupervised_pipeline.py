import os
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

def build_preprocessor(X):
    """Build standardized ColumnTransformer for numerical and categorical features."""
    num_cols = X.select_dtypes(include=['int64', 'float64']).columns.tolist()
    cat_cols = X.select_dtypes(include=['object', 'category', 'string']).columns.tolist()
    
    numeric_transformer = StandardScaler()
    categorical_transformer = OneHotEncoder(handle_unknown='ignore', sparse_output=False)
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, num_cols),
            ('cat', categorical_transformer, cat_cols)
        ]
    )
    return preprocessor, num_cols, cat_cols

def main():
    print("=" * 65)
    print("  CYBERGUARD NIDS — UNSUPERVISED ANOMALY DETECTION PIPELINE")
    print("=" * 65)
    
    # 1. Load Data
    data_path = 'data/cyberguard_synthetic_demo (1).csv' if os.path.exists('data/cyberguard_synthetic_demo (1).csv') else 'cyberguard_synthetic_demo (1).csv'
    df = pd.read_csv(data_path)
    print(f"Loaded dataset: {data_path} ({len(df)} records)")
    
    # Drop artificial ID column
    if 'ID' in df.columns:
        df = df.drop(columns=['ID'])
        
    # Ground truth: 0 = Normal, 1 = Anomaly (Attack)
    attack_types = df['attack_type'].copy()
    y_binary = (attack_types != 'Normal').astype(int)
    X = df.drop(columns=['attack_type'])
    
    # Class distribution
    normal_count = (y_binary == 0).sum()
    anomaly_count = (y_binary == 1).sum()
    contamination_rate = anomaly_count / len(y_binary)
    print(f"Normal Flows: {normal_count} ({normal_count / len(y_binary) * 100:.1f}%)")
    print(f"Anomaly Flows: {anomaly_count} ({anomaly_count / len(y_binary) * 100:.1f}%)")
    print(f"Observed Contamination Rate: {contamination_rate:.4f}\n")
    
    # 2. Train/Test Split (80/20 Stratified)
    X_train, X_test, y_train, y_test, attacks_train, attacks_test = train_test_split(
        X, y_binary, attack_types, test_size=0.2, random_state=42, stratify=y_binary
    )
    
    preprocessor, num_cols, cat_cols = build_preprocessor(X_train)
    
    # 3. Model Definitions
    # Model 1: Isolation Forest (Completely Unsupervised - No Labels in fit())
    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=contamination_rate,
        random_state=42,
        n_jobs=-1
    )
    iso_pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('detector', iso_forest)
    ])
    
    # Model 2: One-Class SVM (Unsupervised Boundary Detection)
    oc_svm = OneClassSVM(
        kernel='rbf',
        gamma='scale',
        nu=contamination_rate
    )
    oc_pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('detector', oc_svm)
    ])
    
    # Model 3: Supervised Baseline (Random Forest trained on binary labels)
    rf_baseline = RandomForestClassifier(
        n_estimators=100,
        class_weight='balanced',
        random_state=42
    )
    rf_pipeline = Pipeline([
        ('preprocessor', preprocessor),
        ('classifier', rf_baseline)
    ])
    
    # 4. Train Models
    print("Training Unsupervised Isolation Forest (No target labels used in training)...")
    iso_pipeline.fit(X_train)  # Unsupervised: fits purely on X_train!
    
    print("Training Unsupervised One-Class SVM...")
    oc_pipeline.fit(X_train)   # Unsupervised
    
    print("Training Supervised Random Forest Baseline (Uses ground truth labels)...")
    rf_pipeline.fit(X_train, y_train)
    
    # 5. Predictions & Mapping
    # In sklearn: IsolationForest & OneClassSVM predict: +1 = inlier (Normal), -1 = outlier (Anomaly)
    # We map: +1 -> 0 (Normal), -1 -> 1 (Anomaly)
    iso_raw_pred = iso_pipeline.predict(X_test)
    iso_preds = np.where(iso_raw_pred == -1, 1, 0)
    iso_scores = -iso_pipeline.named_steps['detector'].decision_function(
        iso_pipeline.named_steps['preprocessor'].transform(X_test)
    )  # Higher score = more anomalous
    
    oc_raw_pred = oc_pipeline.predict(X_test)
    oc_preds = np.where(oc_raw_pred == -1, 1, 0)
    
    rf_preds = rf_pipeline.predict(X_test)
    rf_probs = rf_pipeline.predict_proba(X_test)[:, 1]
    
    # 6. Evaluation Metrics Table
    results = [
        {
            'Algorithm': 'Random Forest (Supervised Baseline)',
            'Learning Paradigm': 'Supervised (Trained on labels)',
            'Accuracy': accuracy_score(y_test, rf_preds),
            'Precision': precision_score(y_test, rf_preds),
            'Recall': recall_score(y_test, rf_preds),
            'F1-Score': f1_score(y_test, rf_preds),
            'ROC-AUC': roc_auc_score(y_test, rf_probs)
        },
        {
            'Algorithm': 'Isolation Forest (Primary)',
            'Learning Paradigm': 'Unsupervised (Zero labels used)',
            'Accuracy': accuracy_score(y_test, iso_preds),
            'Precision': precision_score(y_test, iso_preds),
            'Recall': recall_score(y_test, iso_preds),
            'F1-Score': f1_score(y_test, iso_preds),
            'ROC-AUC': roc_auc_score(y_test, iso_scores)
        },
        {
            'Algorithm': 'One-Class SVM (Secondary)',
            'Learning Paradigm': 'Unsupervised (Zero labels used)',
            'Accuracy': accuracy_score(y_test, oc_preds),
            'Precision': precision_score(y_test, oc_preds),
            'Recall': recall_score(y_test, oc_preds),
            'F1-Score': f1_score(y_test, oc_preds),
            'ROC-AUC': roc_auc_score(y_test, -oc_pipeline.named_steps['detector'].decision_function(
                oc_pipeline.named_steps['preprocessor'].transform(X_test)
            ))
        }
    ]
    
    results_df = pd.DataFrame(results)
    print("\n" + "=" * 80)
    print("                     MODEL COMPARISON ON TEST SET (200 FLOWS)")
    print("=" * 80)
    formatted_df = results_df.copy()
    for col in ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC']:
        formatted_df[col] = formatted_df[col].map(lambda x: f"{x * 100:.2f}%")
    print(formatted_df.to_string(index=False))
    print("=" * 80)
    
    # 7. Breakdown: How well did unsupervised Isolation Forest catch each attack type?
    print("\n=== ISOLATION FOREST: DETECTION RATE BY ATTACK TYPE ===")
    test_eval_df = pd.DataFrame({
        'Actual_Attack': attacks_test.values,
        'Predicted_Anomaly': iso_preds
    })
    
    attack_breakdown = []
    for atk, grp in test_eval_df.groupby('Actual_Attack'):
        total = len(grp)
        detected = (grp['Predicted_Anomaly'] == 1).sum() if atk != 'Normal' else (grp['Predicted_Anomaly'] == 0).sum()
        rate = (detected / total) * 100
        metric_name = "Correctly Identified Normal" if atk == 'Normal' else "Attack Detection Rate"
        attack_breakdown.append({
            'Traffic Type': atk,
            'Total Instances': total,
            'Correctly Flagged': detected,
            'Success Rate': f"{rate:.1f}%",
            'Role': metric_name
        })
    
    breakdown_df = pd.DataFrame(attack_breakdown)
    print(breakdown_df.to_string(index=False))
    
    # 8. Save Isolation Forest Model
    os.makedirs('models', exist_ok=True)
    os.makedirs('outputs', exist_ok=True)
    joblib.dump(iso_pipeline, 'models/isolation_forest_pipeline.pkl')
    print("\nSaved trained unsupervised pipeline -> models/isolation_forest_pipeline.pkl")
    
    # 9. Generate High-Impact Visualizations
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    
    # 1. Confusion Matrix
    cm = confusion_matrix(y_test, iso_preds)
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0, 0],
                xticklabels=['Normal', 'Anomaly'], yticklabels=['Normal', 'Anomaly'])
    axes[0, 0].set_title('Isolation Forest — Confusion Matrix (Unsupervised)', fontsize=13, fontweight='bold')
    axes[0, 0].set_ylabel('Ground Truth')
    axes[0, 0].set_xlabel('Predicted by Isolation Forest')
    
    # 2. Anomaly Score Distribution (Separation between Normal and Attacks)
    score_df = pd.DataFrame({
        'Anomaly Score': iso_scores,
        'Type': np.where(y_test == 0, 'Normal Traffic', 'Cyber Attack')
    })
    sns.kdeplot(data=score_df, x='Anomaly Score', hue='Type', fill=True, common_norm=False, 
                palette={'Normal Traffic': '#2ecc71', 'Cyber Attack': '#e74c3c'}, ax=axes[0, 1])
    axes[0, 1].set_title('Anomaly Score Separation (Normal vs Attacks)', fontsize=13, fontweight='bold')
    axes[0, 1].set_xlabel('Anomaly Score (Higher = More Anomalous)')
    
    # 3. Detection Rate by Attack Category
    non_normal_breakdown = [b for b in attack_breakdown if b['Traffic Type'] != 'Normal']
    atk_names = [b['Traffic Type'] for b in non_normal_breakdown]
    atk_rates = [float(b['Success Rate'].replace('%', '')) for b in non_normal_breakdown]
    
    bars = axes[1, 0].bar(atk_names, atk_rates, color='#3498db', edgecolor='black', alpha=0.85)
    axes[1, 0].axhline(y=100, color='gray', linestyle='--', alpha=0.5)
    axes[1, 0].set_ylim(0, 115)
    axes[1, 0].set_title('Isolation Forest Detection Rate per Attack Class', fontsize=13, fontweight='bold')
    axes[1, 0].set_ylabel('Detection Recall (%)')
    for bar in bars:
        height = bar.get_height()
        axes[1, 0].annotate(f'{height:.1f}%',
                            xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 3), textcoords="offset points",
                            ha='center', va='bottom', fontweight='bold')
    
    # 4. Model Comparison Bar Chart
    comp_df = results_df[['Algorithm', 'Accuracy', 'Recall', 'F1-Score']].melt(
        id_vars='Algorithm', var_name='Metric', value_name='Score'
    )
    sns.barplot(data=comp_df, x='Algorithm', y='Score', hue='Metric', ax=axes[1, 1], palette='Set2')
    axes[1, 1].set_title('Supervised vs Unsupervised Model Comparison', fontsize=13, fontweight='bold')
    axes[1, 1].set_ylim(0, 1.1)
    axes[1, 1].set_xticks(range(len(results_df)))
    axes[1, 1].set_xticklabels(['Random Forest\n(Supervised)', 'Isolation Forest\n(Unsupervised)', 'One-Class SVM\n(Unsupervised)'])
    
    plt.tight_layout()
    chart_path = 'outputs/unsupervised_evaluation.png'
    plt.savefig(chart_path, dpi=300)
    plt.savefig('unsupervised_evaluation.png', dpi=300) # Also save in root for easy access
    print(f"Saved evaluation visualizations -> {chart_path} & unsupervised_evaluation.png")
    
    print("\n" + "=" * 65)
    print(" Unsupervised Evaluation Completed Successfully!")
    print("=" * 65)

if __name__ == '__main__':
    main()
