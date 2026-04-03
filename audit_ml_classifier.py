import os
import json
from typing import Optional, List, Dict, Any, Tuple
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


class AuditDataLeakClassifier:
    """
    Pure data-driven audit classifier (LLM-3 replacement) with:
    - No hardcoded patterns, keywords, or domain definitions
    - No embedded/basic training data or synthetic generation
    - Train exclusively from external data that you provide

    Expected training data schema (JSON list of objects):
      [
        {
          "audit_context": "<string combining role, question, decision, sql preview, answer>",
          "status": "LEAK" | "OK",
          "category": "<any free-form category label or null>"
        },
        ...
      ]

    The model trains two independent pipelines:
      - status_pipeline: predicts LEAK/OK
      - category_pipeline: predicts category label (optional; trained only if labels exist)

    Usage pattern:
      1) Provide training data path and run `train_from_file(path)` once.
      2) Persisted model files will be created (or use custom paths).
      3) In production, only `load_model()` and `audit_interaction(...)` are used.
    """

    def __init__(
        self,
        status_model_path: str | None = None,
        category_model_path: str | None = None,
    ) -> None:
        self.status_model_path = status_model_path or os.getenv("AUDIT_STATUS_MODEL_PATH", "audit_status_model.pkl")
        self.category_model_path = category_model_path or os.getenv("AUDIT_CATEGORY_MODEL_PATH", "audit_category_model.pkl")

        self.status_pipeline: Pipeline | None = None
        self.category_pipeline: Pipeline | None = None


    def train_from_file(self, data_path: str, test_size: float = 0.2, random_state: int = 42) -> None:
        data = self._read_training_data(data_path)
        if not data:
            raise ValueError("No training data found. Provide a non-empty dataset.")

        contexts, status_labels, category_labels = self._extract_fields(data)

        
        X_train, X_test, y_train, y_test = train_test_split(
            contexts, status_labels, test_size=test_size, random_state=random_state, stratify=status_labels
        )
        self.status_pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
            ("clf", LogisticRegression(max_iter=1000)),
        ])
        self.status_pipeline.fit(X_train, y_train)
        y_pred = self.status_pipeline.predict(X_test)
        print("Status model report:\n" + classification_report(y_test, y_pred))
        joblib.dump(self.status_pipeline, self.status_model_path)
        print(f"Saved status model -> {self.status_model_path}")

        
        if any(lbl is not None and str(lbl).strip() for lbl in category_labels):
            contexts_c, category_labels_c = self._filter_nonempty_categories(contexts, category_labels)
            Xc_train, Xc_test, yc_train, yc_test = train_test_split(
                contexts_c, category_labels_c, test_size=test_size, random_state=random_state, stratify=category_labels_c
            )
            self.category_pipeline = Pipeline([
                ("tfidf", TfidfVectorizer(ngram_range=(1, 2))),
                ("clf", LogisticRegression(max_iter=1000)),
            ])
            self.category_pipeline.fit(Xc_train, yc_train)
            yc_pred = self.category_pipeline.predict(Xc_test)
            print("Category model report:\n" + classification_report(yc_test, yc_pred))
            joblib.dump(self.category_pipeline, self.category_model_path)
            print(f"Saved category model -> {self.category_model_path}")
        else:
            self.category_pipeline = None
            
            print("No category labels present. Skipping category model training.")

    def _read_training_data(self, path: str) -> List[Dict[str, Any]]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"Training data not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Training data must be a JSON list of objects")
        return data

    def _extract_fields(self, data: List[Dict[str, Any]]) -> tuple[List[str], List[str], List[Optional[str]]]:
        contexts: List[str] = []
        status_labels: List[str] = []
        category_labels: List[Optional[str]] = []
        for row in data:
            ctx = str(row.get("audit_context", "")).strip()
            status = str(row.get("status", "")).strip()
            category = row.get("category", None)
            if not ctx or not status:
                
                continue
            contexts.append(ctx)
            status_labels.append(status)
            category_labels.append((str(category).strip() if category is not None else None))
        if not contexts:
            raise ValueError("Training data had no valid rows (missing audit_context/status)")
        return contexts, status_labels, category_labels

    def _filter_nonempty_categories(self, contexts: List[str], categories: List[Optional[str]]) -> tuple[List[str], List[str]]:
        X: List[str] = []
        y: List[str] = []
        for c, k in zip(contexts, categories):
            if k is not None and str(k).strip():
                X.append(c)
                y.append(str(k).strip())
        if not X:
            raise ValueError("No non-empty category labels were found")
        return X, y

    

    def load_model(self) -> None:
        if os.path.exists(self.status_model_path):
            self.status_pipeline = joblib.load(self.status_model_path)
        else:
            self.status_pipeline = None
        if os.path.exists(self.category_model_path):
            self.category_pipeline = joblib.load(self.category_model_path)
        else:
            self.category_pipeline = None

    def is_ready(self) -> bool:
        return self.status_pipeline is not None

    def audit_interaction(
        self,
        role: str,
        question: str,
        classifier_decision: str,
        sql: str,
        headers: List[str],
        rows: List[List[Any]],
        answer_text: str,
    ) -> Tuple[str, Optional[str]]:
        """
        Predict (status, category) from the combined audit context.
        Returns ("LEAK"|"OK", category_or_None)
        """
        if self.status_pipeline is None:
            raise RuntimeError("Audit classifier not ready. Train and/or load the model first.")

        preview_lines = [" | ".join(map(str, headers))]
        for r in rows[:5]:
            preview_lines.append(" | ".join(str(x) if x is not None else "" for x in r))
        preview = "\n".join(preview_lines)

        audit_context = (
            f"Role: {role}\n"
            f"Question: {question}\n"
            f"ClassifierDecision: {classifier_decision}\n"
            f"SQL: {sql}\n"
            f"Preview:\n{preview}\n"
            f"Answer: {answer_text}"
        )

        status = self.status_pipeline.predict([audit_context])[0]

        category: Optional[str] = None
        if self.category_pipeline is not None:
            category = self.category_pipeline.predict([audit_context])[0]

        return str(status), (str(category) if category is not None else None)



_audit_classifier_singleton: AuditDataLeakClassifier | None = None

def get_audit_classifier() -> AuditDataLeakClassifier:
    global _audit_classifier_singleton
    if _audit_classifier_singleton is None:
        _audit_classifier_singleton = AuditDataLeakClassifier()
        try:
            _audit_classifier_singleton.load_model()
        except Exception:
            pass
    return _audit_classifier_singleton
